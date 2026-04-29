package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

type ExamService interface {
	CreateExam(ctx context.Context, req CreateExamRequest) (*models.Exam, error)
	GetExamByID(ctx context.Context, id uuid.UUID) (*models.Exam, error)
	ListExams(ctx context.Context, filter repository.ExamFilter, p repository.Pagination, s repository.Sort) ([]*models.Exam, error)
	UpdateExam(ctx context.Context, req UpdateExamRequest) (*models.Exam, error)
	DeleteExam(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	CreateExamSchedule(ctx context.Context, req CreateExamScheduleRequest) (*models.ExamSchedule, error)
	GetExamScheduleByID(ctx context.Context, id uuid.UUID) (*models.ExamSchedule, error)
	ListExamSchedules(ctx context.Context, filter repository.ExamScheduleFilter, p repository.Pagination, s repository.Sort) ([]*models.ExamSchedule, error)
	UpdateExamSchedule(ctx context.Context, req UpdateExamScheduleRequest) (*models.ExamSchedule, error)
	DeleteExamSchedule(ctx context.Context, id uuid.UUID) error
	CreateExamResult(ctx context.Context, req CreateExamResultRequest) (*models.ExamResult, error)
	BulkCreateExamResults(ctx context.Context, reqs []CreateExamResultRequest) ([]*models.ExamResult, error)
	GetExamResultByID(ctx context.Context, id uuid.UUID) (*models.ExamResult, error)
	ListExamResults(ctx context.Context, filter repository.ExamResultFilter, p repository.Pagination, s repository.Sort) ([]*models.ExamResult, error)
	UpdateExamResult(ctx context.Context, req UpdateExamResultRequest) (*models.ExamResult, error)
	DeleteExamResult(ctx context.Context, id uuid.UUID) error
	CreateExamGrade(ctx context.Context, req CreateExamGradeRequest) (*models.ExamGrade, error)
	GetExamGradeByID(ctx context.Context, id uuid.UUID) (*models.ExamGrade, error)
	ListExamGrades(ctx context.Context, filter repository.ExamGradeFilter, p repository.Pagination, s repository.Sort) ([]*models.ExamGrade, error)
	UpdateExamGrade(ctx context.Context, req UpdateExamGradeRequest) (*models.ExamGrade, error)
	DeleteExamGrade(ctx context.Context, id uuid.UUID) error
}

type examService struct {
	repo             repository.ExamRepository
	termRepo         repository.TermRepository
	academicYearRepo repository.AcademicYearRepository
	subjectRepo      repository.SubjectRepository
	enrollmentRepo   repository.EnrollmentRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	notifSvc         NotificationService
}

func NewExamService(
	repo repository.ExamRepository,
	termRepo repository.TermRepository,
	academicYearRepo repository.AcademicYearRepository,
	subjectRepo repository.SubjectRepository,
	enrollmentRepo repository.EnrollmentRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	notifSvc NotificationService,
) ExamService {
	return &examService{
		repo:             repo,
		termRepo:         termRepo,
		academicYearRepo: academicYearRepo,
		subjectRepo:      subjectRepo,
		enrollmentRepo:   enrollmentRepo,
		pgClient:         pgClient,
		logger:           logger.Named("exam_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		notifSvc:         notifSvc,
	}
}

// ----------------------------------------------------------------------
// Helper functions (shared)
// ----------------------------------------------------------------------

func (s *examService) getStudentIDsForTerm(ctx context.Context, termID uuid.UUID) ([]uuid.UUID, error) {
	query := `
		SELECT DISTINCT e.student_id
		FROM academics.enrollments e
		JOIN academics.section sec ON e.section_id = sec.section_id
		WHERE sec.term_id = $1
		  AND sec.deleted_at IS NULL
	`
	rows, err := s.pgClient.DB.QueryContext(ctx, query, termID)
	if err != nil {
		return nil, fmt.Errorf("query student IDs for term %s: %w", termID, err)
	}
	defer rows.Close()
	var studentIDs []uuid.UUID
	for rows.Next() {
		var sid uuid.UUID
		if err := rows.Scan(&sid); err != nil {
			return nil, fmt.Errorf("scan student ID: %w", err)
		}
		studentIDs = append(studentIDs, sid)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return studentIDs, nil
}

func (s *examService) getCompanyIDForTerm(ctx context.Context, termID uuid.UUID) (uuid.UUID, error) {
	term, err := s.termRepo.GetByID(ctx, s.pgClient.DB, termID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("get term %s: %w", termID, err)
	}
	if term == nil {
		return uuid.Nil, fmt.Errorf("term %s not found", termID)
	}
	academicYear, err := s.academicYearRepo.GetByID(ctx, s.pgClient.DB, term.AcademicYearID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("get academic year %s: %w", term.AcademicYearID, err)
	}
	if academicYear == nil {
		return uuid.Nil, fmt.Errorf("academic year %s not found", term.AcademicYearID)
	}
	return academicYear.CompanyID, nil
}

func (s *examService) createNotification(ctx context.Context, companyID uuid.UUID, title, message string,
	notifType models.NotificationType, priority models.NotificationPriority,
	studentIDs []uuid.UUID, createdBy *uuid.UUID) {
	if s.notifSvc == nil || len(studentIDs) == 0 {
		return
	}
	targets := make([]NotificationTargetInput, len(studentIDs))
	for i, sid := range studentIDs {
		targets[i] = NotificationTargetInput{
			TargetType:     models.TargetStudent,
			TargetEntityID: sid,
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
	_, err := s.notifSvc.Create(context.Background(), req, "")
	if err != nil {
		s.logger.Error("failed to send notification",
			zap.String("title", title),
			zap.Error(err))
	}
}

// ----------------------------------------------------------------------
// Exam CRUD
// ----------------------------------------------------------------------

func (s *examService) CreateExam(ctx context.Context, req CreateExamRequest) (*models.Exam, error) {
	logger := s.logger.With(
		zap.String("method", "CreateExam"),
		zap.String("academic_year_id", req.AcademicYearID.String()),
		zap.String("term_id", req.TermID.String()),
		zap.String("exam_name", req.ExamName),
	)

	if err := s.validateExamCreate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
		var existing *models.Exam
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	term, err := s.termRepo.GetByID(ctx, tx, req.TermID)
	if err != nil {
		return nil, err
	}
	if term == nil {
		return nil, fmt.Errorf("%w: term %s", ErrNotFound, req.TermID)
	}
	if term.AcademicYearID != req.AcademicYearID {
		return nil, fmt.Errorf("%w: term does not belong to the specified academic year", ErrInvalidInput)
	}
	if req.StartDate.Before(term.StartDate) || req.EndDate.After(term.EndDate) {
		return nil, fmt.Errorf("%w: exam dates must be within term (%s - %s)", ErrInvalidInput, term.StartDate, term.EndDate)
	}

	exam := &models.Exam{
		AcademicYearID: req.AcademicYearID,
		TermID:         req.TermID,
		ExamName:       req.ExamName,
		StartDate:      req.StartDate,
		EndDate:        req.EndDate,
		Description:    req.Description,
		IsActive:       req.IsActive,
		CreatedBy:      req.CreatedBy,
		UpdatedBy:      req.UpdatedBy,
	}

	if err := s.repo.CreateExam(ctx, tx, exam); err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return nil, fmt.Errorf("%w: exam name already exists in this term", ErrDuplicate)
		}
		return nil, err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "create", "exam",
			&exam.ExamID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"name": exam.ExamName})
	}

	payload, _ := json.Marshal(exam)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "exam",
		AggregateID:   exam.ExamID.String(),
		EventType:     string(EventExamCreated),
		Topic:         TopicExam, // <-- ADDED
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, exam); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	studentIDs, _ := s.getStudentIDsForTerm(ctx, term.TermID)
	companyID, _ := s.getCompanyIDForTerm(ctx, term.TermID)
	if companyID != uuid.Nil {
		title := fmt.Sprintf("New Exam: %s", exam.ExamName)
		message := fmt.Sprintf("A new exam '%s' has been scheduled from %s to %s.", exam.ExamName, exam.StartDate.Format("2006-01-02"), exam.EndDate.Format("2006-01-02"))
		s.createNotification(ctx, companyID, title, message, models.NotificationTypeEvent, models.PriorityNormal, studentIDs, req.CreatedBy)
	}

	logger.Info("exam created", zap.String("exam_id", exam.ExamID.String()))
	return exam, nil
}

func (s *examService) GetExamByID(ctx context.Context, id uuid.UUID) (*models.Exam, error) {
	exam, err := s.repo.GetExamByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if exam == nil {
		return nil, fmt.Errorf("%w: exam %s", ErrNotFound, id)
	}
	return exam, nil
}

func (s *examService) ListExams(ctx context.Context, filter repository.ExamFilter, p repository.Pagination, srt repository.Sort) ([]*models.Exam, error) {
	return s.repo.ListExams(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *examService) UpdateExam(ctx context.Context, req UpdateExamRequest) (*models.Exam, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateExam"),
		zap.String("exam_id", req.ExamID.String()),
	)

	if req.ExamID == uuid.Nil {
		return nil, fmt.Errorf("%w: exam_id is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	exam, err := s.repo.GetExamByID(ctx, tx, req.ExamID)
	if err != nil {
		return nil, err
	}
	if exam == nil {
		return nil, fmt.Errorf("%w: exam %s", ErrNotFound, req.ExamID)
	}

	if req.TermID != exam.TermID {
		term, err := s.termRepo.GetByID(ctx, tx, req.TermID)
		if err != nil || term == nil {
			return nil, fmt.Errorf("%w: term %s", ErrNotFound, req.TermID)
		}
		if term.AcademicYearID != exam.AcademicYearID {
			return nil, fmt.Errorf("%w: term does not belong to the exam's academic year", ErrInvalidInput)
		}
		if req.StartDate.Before(term.StartDate) || req.EndDate.After(term.EndDate) {
			return nil, fmt.Errorf("%w: exam dates must be within term (%s - %s)", ErrInvalidInput, term.StartDate, term.EndDate)
		}
	} else {
		term, err := s.termRepo.GetByID(ctx, tx, exam.TermID)
		if err != nil || term == nil {
			return nil, fmt.Errorf("%w: term %s", ErrNotFound, exam.TermID)
		}
		if req.StartDate.Before(term.StartDate) || req.EndDate.After(term.EndDate) {
			return nil, fmt.Errorf("%w: exam dates must be within term (%s - %s)", ErrInvalidInput, term.StartDate, term.EndDate)
		}
	}

	if req.ExamName != exam.ExamName {
		filter := repository.ExamFilter{
			TermID: &req.TermID,
			Search: req.ExamName,
		}
		existing, err := s.repo.ListExams(ctx, tx, filter, repository.Pagination{Limit: 1}, repository.Sort{})
		if err != nil {
			return nil, err
		}
		if len(existing) > 0 && existing[0].ExamID != req.ExamID {
			return nil, fmt.Errorf("%w: exam name %s already exists in this term", ErrDuplicate, req.ExamName)
		}
	}

	oldExam := *exam
	exam.TermID = req.TermID
	exam.ExamName = req.ExamName
	exam.StartDate = req.StartDate
	exam.EndDate = req.EndDate
	exam.Description = req.Description
	exam.IsActive = req.IsActive
	exam.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateExam(ctx, tx, exam); err != nil {
		return nil, err
	}

	if s.auditService != nil {
		oldExamJSON, _ := json.Marshal(oldExam)
		examJSON, _ := json.Marshal(exam)
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "update", "exam",
			&exam.ExamID, "user", req.UpdatedBy, oldExamJSON, examJSON, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"old": oldExam,
		"new": exam,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "exam",
		AggregateID:   exam.ExamID.String(),
		EventType:     string(EventExamUpdated),
		Topic:         TopicExam, // <-- ADDED
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("exam updated")
	return exam, nil
}

func (s *examService) DeleteExam(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteExam"),
		zap.String("exam_id", id.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	schedules, err := s.repo.GetExamSchedulesByExam(ctx, tx, id)
	if err != nil {
		return err
	}
	if len(schedules) > 0 {
		return fmt.Errorf("%w: exam has %d schedules, delete them first", ErrDependencyExists, len(schedules))
	}

	if err := s.repo.DeleteExam(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "delete", "exam",
			&id, "user", deletedBy, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"exam_id":    id,
		"deleted_by": deletedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "exam",
		AggregateID:   id.String(),
		EventType:     string(EventExamDeleted),
		Topic:         TopicExam, // <-- ADDED
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("exam deleted")
	return nil
}

// ----------------------------------------------------------------------
// Exam Schedule (idempotency added)
// ----------------------------------------------------------------------

func (s *examService) CreateExamSchedule(ctx context.Context, req CreateExamScheduleRequest) (*models.ExamSchedule, error) {
	logger := s.logger.With(
		zap.String("method", "CreateExamSchedule"),
		zap.String("exam_id", req.ExamID.String()),
		zap.String("subject_id", req.SubjectID.String()),
	)

	if err := s.validateExamScheduleCreate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
		var existing *models.ExamSchedule
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	exam, err := s.repo.GetExamByID(ctx, tx, req.ExamID)
	if err != nil {
		return nil, err
	}
	if exam == nil {
		return nil, fmt.Errorf("%w: exam %s", ErrNotFound, req.ExamID)
	}

	subject, err := s.subjectRepo.GetByID(ctx, tx, req.SubjectID)
	if err != nil {
		return nil, err
	}
	if subject == nil {
		return nil, fmt.Errorf("%w: subject %s", ErrNotFound, req.SubjectID)
	}

	if req.Date.Before(exam.StartDate) || req.Date.After(exam.EndDate) {
		return nil, fmt.Errorf("%w: schedule date must be within exam period %s - %s", ErrInvalidInput, exam.StartDate, exam.EndDate)
	}

	schedule := &models.ExamSchedule{
		ExamID:       req.ExamID,
		SubjectID:    req.SubjectID,
		Date:         req.Date,
		StartTime:    req.StartTime,
		EndTime:      req.EndTime,
		RoomID:       req.RoomID,
		MaxMarks:     req.MaxMarks,
		PassingMarks: req.PassingMarks,
		CreatedBy:    req.CreatedBy,
		UpdatedBy:    req.UpdatedBy,
	}

	if err := s.repo.CreateExamSchedule(ctx, tx, schedule); err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return nil, fmt.Errorf("%w: schedule for this subject already exists on this date", ErrDuplicate)
		}
		return nil, err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "create_schedule", "exam_schedule",
			&schedule.ScheduleID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"exam_id": req.ExamID, "subject_id": req.SubjectID})
	}

	payload, _ := json.Marshal(schedule)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "exam_schedule",
		AggregateID:   schedule.ScheduleID.String(),
		EventType:     string(EventExamScheduleCreated),
		Topic:         TopicExamSchedule, // <-- ADDED
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, schedule); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	studentIDs, _ := s.getStudentIDsForTerm(ctx, exam.TermID)
	companyID, _ := s.getCompanyIDForTerm(ctx, exam.TermID)
	if companyID != uuid.Nil {
		title := fmt.Sprintf("Exam Schedule: %s - %s", exam.ExamName, subject.Name)
		message := fmt.Sprintf("The exam for %s is scheduled on %s. Start time: %v, End time: %v, Room: %v.",
			subject.Name, schedule.Date.Format("2006-01-02"), schedule.StartTime, schedule.EndTime, schedule.RoomID)
		s.createNotification(ctx, companyID, title, message, models.NotificationTypeEvent, models.PriorityNormal, studentIDs, req.CreatedBy)
	}

	logger.Info("exam schedule created", zap.String("schedule_id", schedule.ScheduleID.String()))
	return schedule, nil
}

func (s *examService) GetExamScheduleByID(ctx context.Context, id uuid.UUID) (*models.ExamSchedule, error) {
	schedule, err := s.repo.GetExamScheduleByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if schedule == nil {
		return nil, fmt.Errorf("%w: exam schedule %s", ErrNotFound, id)
	}
	return schedule, nil
}

func (s *examService) ListExamSchedules(ctx context.Context, filter repository.ExamScheduleFilter, p repository.Pagination, srt repository.Sort) ([]*models.ExamSchedule, error) {
	return s.repo.ListExamSchedules(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *examService) UpdateExamSchedule(ctx context.Context, req UpdateExamScheduleRequest) (*models.ExamSchedule, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateExamSchedule"),
		zap.String("schedule_id", req.ScheduleID.String()),
	)

	if req.ScheduleID == uuid.Nil {
		return nil, fmt.Errorf("%w: schedule_id is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	schedule, err := s.repo.GetExamScheduleByID(ctx, tx, req.ScheduleID)
	if err != nil {
		return nil, err
	}
	if schedule == nil {
		return nil, fmt.Errorf("%w: exam schedule %s", ErrNotFound, req.ScheduleID)
	}

	if req.SubjectID != schedule.SubjectID {
		subject, err := s.subjectRepo.GetByID(ctx, tx, req.SubjectID)
		if err != nil || subject == nil {
			return nil, fmt.Errorf("%w: subject %s", ErrNotFound, req.SubjectID)
		}
	}

	exam, err := s.repo.GetExamByID(ctx, tx, schedule.ExamID)
	if err != nil {
		return nil, err
	}
	if req.Date.Before(exam.StartDate) || req.Date.After(exam.EndDate) {
		return nil, fmt.Errorf("%w: schedule date must be within exam period %s - %s", ErrInvalidInput, exam.StartDate, exam.EndDate)
	}

	oldSchedule := *schedule
	schedule.SubjectID = req.SubjectID
	schedule.Date = req.Date
	schedule.StartTime = req.StartTime
	schedule.EndTime = req.EndTime
	schedule.RoomID = req.RoomID
	schedule.MaxMarks = req.MaxMarks
	schedule.PassingMarks = req.PassingMarks
	schedule.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateExamSchedule(ctx, tx, schedule); err != nil {
		return nil, err
	}

	if s.auditService != nil {
		oldScheduleJSON, _ := json.Marshal(oldSchedule)
		scheduleJSON, _ := json.Marshal(schedule)
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "update_schedule", "exam_schedule",
			&schedule.ScheduleID, "user", req.UpdatedBy, oldScheduleJSON, scheduleJSON, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"old": oldSchedule,
		"new": schedule,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "exam_schedule",
		AggregateID:   schedule.ScheduleID.String(),
		EventType:     string(EventExamScheduleUpdated),
		Topic:         TopicExamSchedule, // <-- ADDED
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("exam schedule updated")
	return schedule, nil
}

func (s *examService) DeleteExamSchedule(ctx context.Context, id uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteExamSchedule"),
		zap.String("schedule_id", id.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteExamSchedule(ctx, tx, id); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "delete_schedule", "exam_schedule",
			&id, "user", nil, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"schedule_id": id,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "exam_schedule",
		AggregateID:   id.String(),
		EventType:     string(EventExamScheduleDeleted),
		Topic:         TopicExamSchedule, // <-- ADDED
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("exam schedule deleted")
	return nil
}

// ----------------------------------------------------------------------
// Exam Result (idempotency added)
// ----------------------------------------------------------------------

func (s *examService) CreateExamResult(ctx context.Context, req CreateExamResultRequest) (*models.ExamResult, error) {
	logger := s.logger.With(
		zap.String("method", "CreateExamResult"),
		zap.String("exam_id", req.ExamID.String()),
		zap.String("enrollment_id", req.EnrollmentID.String()),
		zap.String("subject_id", req.SubjectID.String()),
	)

	if err := s.validateExamResultCreate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
		var existing *models.ExamResult
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	exam, err := s.repo.GetExamByID(ctx, tx, req.ExamID)
	if err != nil || exam == nil {
		return nil, fmt.Errorf("%w: exam %s", ErrNotFound, req.ExamID)
	}

	enrollment, err := s.enrollmentRepo.GetByIDUnsafe(ctx, tx, req.EnrollmentID)
	if err != nil {
		return nil, err
	}
	if enrollment == nil {
		return nil, fmt.Errorf("%w: enrollment %s", ErrNotFound, req.EnrollmentID)
	}

	schedules, err := s.repo.GetExamSchedulesByExam(ctx, tx, req.ExamID)
	if err != nil {
		return nil, err
	}
	found := false
	for _, sched := range schedules {
		if sched.SubjectID == req.SubjectID {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("%w: subject %s not scheduled for this exam", ErrInvalidInput, req.SubjectID)
	}

	existingResults, err := s.repo.GetExamResultsByExamAndEnrollment(ctx, tx, req.ExamID, req.EnrollmentID)
	if err != nil {
		return nil, err
	}
	for _, r := range existingResults {
		if r.SubjectID == req.SubjectID {
			return nil, fmt.Errorf("%w: result already exists for this subject and exam", ErrDuplicate)
		}
	}

	result := &models.ExamResult{
		ExamID:        req.ExamID,
		EnrollmentID:  req.EnrollmentID,
		SubjectID:     req.SubjectID,
		MarksObtained: req.MarksObtained,
		Grade:         req.Grade,
		Remarks:       req.Remarks,
		EnteredBy:     req.EnteredBy,
		EnteredAt:     time.Now(),
		CreatedBy:     req.CreatedBy,
	}

	if err := s.repo.CreateExamResult(ctx, tx, result); err != nil {
		return nil, err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "create_result", "exam_result",
			&result.ResultID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"exam_id": req.ExamID, "subject_id": req.SubjectID})
	}

	payload, _ := json.Marshal(result)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "exam_result",
		AggregateID:   result.ResultID.String(),
		EventType:     string(EventExamResultCreated),
		Topic:         TopicExamResult, // <-- ADDED
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, result); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	studentID := enrollment.StudentID
	companyID, _ := s.getCompanyIDForTerm(ctx, exam.TermID)
	if companyID != uuid.Nil && studentID != uuid.Nil {
		title := fmt.Sprintf("Exam Result Published: %s", exam.ExamName)
		message := fmt.Sprintf("Your result for %s has been published. Marks obtained: %v, Grade: %s.",
			exam.ExamName, result.MarksObtained, result.Grade)
		s.createNotification(ctx, companyID, title, message, models.NotificationTypeInfo, models.PriorityNormal, []uuid.UUID{studentID}, req.CreatedBy)
	}

	logger.Info("exam result created", zap.String("result_id", result.ResultID.String()))
	return result, nil
}

func (s *examService) BulkCreateExamResults(ctx context.Context, reqs []CreateExamResultRequest) ([]*models.ExamResult, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	logger := s.logger.With(zap.String("method", "BulkCreateExamResults"), zap.Int("count", len(reqs)))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
		var existing []*models.ExamResult
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent bulk request, returning cached response")
			return existing, nil
		}
	}

	for i, req := range reqs {
		if err := s.validateExamResultCreate(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
	}

	examSchedulesMap := make(map[uuid.UUID][]uuid.UUID)
	examIDs := make(map[uuid.UUID]struct{})
	for _, req := range reqs {
		examIDs[req.ExamID] = struct{}{}
	}
	for examID := range examIDs {
		schedules, err := s.repo.GetExamSchedulesByExam(ctx, tx, examID)
		if err != nil {
			return nil, err
		}
		subjects := make([]uuid.UUID, len(schedules))
		for i, sched := range schedules {
			subjects[i] = sched.SubjectID
		}
		examSchedulesMap[examID] = subjects
	}

	type key struct {
		ExamID       uuid.UUID
		EnrollmentID uuid.UUID
		SubjectID    uuid.UUID
	}
	seen := make(map[key]bool)
	results := make([]*models.ExamResult, 0, len(reqs))
	for _, req := range reqs {
		k := key{ExamID: req.ExamID, EnrollmentID: req.EnrollmentID, SubjectID: req.SubjectID}
		if seen[k] {
			return nil, fmt.Errorf("duplicate result for exam %s, enrollment %s, subject %s in batch", req.ExamID, req.EnrollmentID, req.SubjectID)
		}
		seen[k] = true

		found := false
		for _, subj := range examSchedulesMap[req.ExamID] {
			if subj == req.SubjectID {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("subject %s not scheduled for exam %s", req.SubjectID, req.ExamID)
		}

		existing, err := s.repo.GetExamResultsByExamAndEnrollment(ctx, tx, req.ExamID, req.EnrollmentID)
		if err != nil {
			return nil, err
		}
		for _, r := range existing {
			if r.SubjectID == req.SubjectID {
				return nil, fmt.Errorf("result already exists for exam %s, enrollment %s, subject %s", req.ExamID, req.EnrollmentID, req.SubjectID)
			}
		}

		results = append(results, &models.ExamResult{
			ExamID:        req.ExamID,
			EnrollmentID:  req.EnrollmentID,
			SubjectID:     req.SubjectID,
			MarksObtained: req.MarksObtained,
			Grade:         req.Grade,
			Remarks:       req.Remarks,
			EnteredBy:     req.EnteredBy,
			EnteredAt:     time.Now(),
			CreatedBy:     req.CreatedBy,
		})
	}

	if err := s.repo.BulkCreateExamResults(ctx, tx, results); err != nil {
		return nil, err
	}

	for _, res := range results {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, tx, nil, "academics", "bulk_create_result", "exam_result",
				&res.ResultID, "user", res.CreatedBy, nil, nil, nil)
		}
		payload, _ := json.Marshal(res)
		outboxEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "exam_result",
			AggregateID:   res.ResultID.String(),
			EventType:     string(EventExamResultCreated),
			Topic:         TopicExamResult, // <-- ADDED
			Payload:       payload,
			Status:        "pending",
		}
		if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
			return nil, fmt.Errorf("store outbox event for result %s: %w", res.ResultID, err)
		}
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, results); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	for _, res := range results {
		enrollment, _ := s.enrollmentRepo.GetByIDUnsafe(ctx, s.pgClient.DB, res.EnrollmentID)
		if enrollment == nil {
			continue
		}
		exam, _ := s.repo.GetExamByID(ctx, s.pgClient.DB, res.ExamID)
		if exam == nil {
			continue
		}
		companyID, _ := s.getCompanyIDForTerm(ctx, exam.TermID)
		if companyID != uuid.Nil {
			studentID := enrollment.StudentID
			if studentID != uuid.Nil {
				title := fmt.Sprintf("Exam Result Published: %s", exam.ExamName)
				message := fmt.Sprintf("Your result for %s has been published. Marks obtained: %v, Grade: %s.",
					exam.ExamName, res.MarksObtained, res.Grade)
				s.createNotification(ctx, companyID, title, message, models.NotificationTypeInfo, models.PriorityNormal, []uuid.UUID{studentID}, res.CreatedBy)
			}
		}
	}

	logger.Info("bulk created exam results", zap.Int("count", len(results)))
	return results, nil
}

func (s *examService) GetExamResultByID(ctx context.Context, id uuid.UUID) (*models.ExamResult, error) {
	res, err := s.repo.GetExamResultByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, fmt.Errorf("%w: exam result %s", ErrNotFound, id)
	}
	return res, nil
}

func (s *examService) ListExamResults(ctx context.Context, filter repository.ExamResultFilter, p repository.Pagination, srt repository.Sort) ([]*models.ExamResult, error) {
	return s.repo.ListExamResults(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *examService) UpdateExamResult(ctx context.Context, req UpdateExamResultRequest) (*models.ExamResult, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateExamResult"),
		zap.String("result_id", req.ResultID.String()),
	)

	if req.ResultID == uuid.Nil {
		return nil, fmt.Errorf("%w: result_id is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	res, err := s.repo.GetExamResultByID(ctx, tx, req.ResultID)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, fmt.Errorf("%w: exam result %s", ErrNotFound, req.ResultID)
	}

	oldRes := *res
	res.MarksObtained = req.MarksObtained
	res.Grade = req.Grade
	res.Remarks = req.Remarks
	res.EnteredBy = req.EnteredBy
	res.EnteredAt = time.Now()

	if err := s.repo.UpdateExamResult(ctx, tx, res); err != nil {
		return nil, err
	}

	if s.auditService != nil {
		oldResJSON, _ := json.Marshal(oldRes)
		resJSON, _ := json.Marshal(res)
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "update_result", "exam_result",
			&res.ResultID, "user", req.UpdatedBy, oldResJSON, resJSON, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"old": oldRes,
		"new": res,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "exam_result",
		AggregateID:   res.ResultID.String(),
		EventType:     string(EventExamResultUpdated),
		Topic:         TopicExamResult, // <-- ADDED
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("exam result updated")
	return res, nil
}

func (s *examService) DeleteExamResult(ctx context.Context, id uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteExamResult"),
		zap.String("result_id", id.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteExamResult(ctx, tx, id); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "delete_result", "exam_result",
			&id, "user", nil, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"result_id": id,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "exam_result",
		AggregateID:   id.String(),
		EventType:     string(EventExamResultDeleted),
		Topic:         TopicExamResult, // <-- ADDED
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("exam result deleted")
	return nil
}

// ----------------------------------------------------------------------
// Exam Grade (idempotency added)
// ----------------------------------------------------------------------

func (s *examService) CreateExamGrade(ctx context.Context, req CreateExamGradeRequest) (*models.ExamGrade, error) {
	logger := s.logger.With(
		zap.String("method", "CreateExamGrade"),
		zap.String("exam_id", req.ExamID.String()),
		zap.String("grade_name", req.GradeName),
	)

	if err := s.validateExamGradeCreate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
		var existing *models.ExamGrade
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	exam, err := s.repo.GetExamByID(ctx, tx, req.ExamID)
	if err != nil || exam == nil {
		return nil, fmt.Errorf("%w: exam %s", ErrNotFound, req.ExamID)
	}

	existingGrades, err := s.repo.ListExamGrades(ctx, tx, repository.ExamGradeFilter{ExamID: req.ExamID}, repository.Pagination{Limit: 1000}, repository.Sort{})
	if err != nil {
		return nil, err
	}
	for _, g := range existingGrades {
		if (req.MinMarks >= g.MinMarks && req.MinMarks <= g.MaxMarks) ||
			(req.MaxMarks >= g.MinMarks && req.MaxMarks <= g.MaxMarks) ||
			(req.MinMarks <= g.MinMarks && req.MaxMarks >= g.MaxMarks) {
			return nil, fmt.Errorf("%w: grade range overlaps with existing grade %s (%f-%f)", ErrOverlap, g.GradeName, g.MinMarks, g.MaxMarks)
		}
	}

	grade := &models.ExamGrade{
		ExamID:     req.ExamID,
		GradeName:  req.GradeName,
		MinMarks:   req.MinMarks,
		MaxMarks:   req.MaxMarks,
		GradePoint: req.GradePoint,
		CreatedAt:  time.Now(),
	}

	if err := s.repo.CreateExamGrade(ctx, tx, grade); err != nil {
		return nil, err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "create_grade", "exam_grade",
			&grade.GradeID, "user", req.CreatedBy, nil, nil, map[string]interface{}{"grade_name": req.GradeName})
	}

	payload, _ := json.Marshal(grade)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "exam_grade",
		AggregateID:   grade.GradeID.String(),
		EventType:     string(EventExamGradeCreated),
		Topic:         TopicExamGrade, // <-- ADDED
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, grade); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("exam grade created", zap.String("grade_id", grade.GradeID.String()))
	return grade, nil
}

func (s *examService) GetExamGradeByID(ctx context.Context, id uuid.UUID) (*models.ExamGrade, error) {
	grade, err := s.repo.GetExamGradeByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if grade == nil {
		return nil, fmt.Errorf("%w: exam grade %s", ErrNotFound, id)
	}
	return grade, nil
}

func (s *examService) ListExamGrades(ctx context.Context, filter repository.ExamGradeFilter, p repository.Pagination, srt repository.Sort) ([]*models.ExamGrade, error) {
	return s.repo.ListExamGrades(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *examService) UpdateExamGrade(ctx context.Context, req UpdateExamGradeRequest) (*models.ExamGrade, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateExamGrade"),
		zap.String("grade_id", req.GradeID.String()),
	)

	if req.GradeID == uuid.Nil {
		return nil, fmt.Errorf("%w: grade_id is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	grade, err := s.repo.GetExamGradeByID(ctx, tx, req.GradeID)
	if err != nil {
		return nil, err
	}
	if grade == nil {
		return nil, fmt.Errorf("%w: exam grade %s", ErrNotFound, req.GradeID)
	}

	existingGrades, err := s.repo.ListExamGrades(ctx, tx, repository.ExamGradeFilter{ExamID: grade.ExamID}, repository.Pagination{Limit: 1000}, repository.Sort{})
	if err != nil {
		return nil, err
	}
	for _, g := range existingGrades {
		if g.GradeID == req.GradeID {
			continue
		}
		if (req.MinMarks >= g.MinMarks && req.MinMarks <= g.MaxMarks) ||
			(req.MaxMarks >= g.MinMarks && req.MaxMarks <= g.MaxMarks) ||
			(req.MinMarks <= g.MinMarks && req.MaxMarks >= g.MaxMarks) {
			return nil, fmt.Errorf("%w: grade range overlaps with existing grade %s (%f-%f)", ErrOverlap, g.GradeName, g.MinMarks, g.MaxMarks)
		}
	}

	oldGrade := *grade
	grade.GradeName = req.GradeName
	grade.MinMarks = req.MinMarks
	grade.MaxMarks = req.MaxMarks
	grade.GradePoint = req.GradePoint

	if err := s.repo.UpdateExamGrade(ctx, tx, grade); err != nil {
		return nil, err
	}

	if s.auditService != nil {
		oldGradeJSON, _ := json.Marshal(oldGrade)
		gradeJSON, _ := json.Marshal(grade)
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "update_grade", "exam_grade",
			&grade.GradeID, "user", req.UpdatedBy, oldGradeJSON, gradeJSON, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"old": oldGrade,
		"new": grade,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "exam_grade",
		AggregateID:   grade.GradeID.String(),
		EventType:     string(EventExamGradeUpdated),
		Topic:         TopicExamGrade, // <-- ADDED
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("exam grade updated")
	return grade, nil
}

func (s *examService) DeleteExamGrade(ctx context.Context, id uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteExamGrade"),
		zap.String("grade_id", id.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteExamGrade(ctx, tx, id); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "delete_grade", "exam_grade",
			&id, "user", nil, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"grade_id": id,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "exam_grade",
		AggregateID:   id.String(),
		EventType:     string(EventExamGradeDeleted),
		Topic:         TopicExamGrade, // <-- ADDED
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("exam grade deleted")
	return nil
}

// ----------------------------------------------------------------------
// Validation helpers
// ----------------------------------------------------------------------

func (s *examService) validateExamCreate(req CreateExamRequest) error {
	if req.AcademicYearID == uuid.Nil {
		return fmt.Errorf("%w: academic_year_id is required", ErrInvalidInput)
	}
	if req.TermID == uuid.Nil {
		return fmt.Errorf("%w: term_id is required", ErrInvalidInput)
	}
	if req.ExamName == "" {
		return fmt.Errorf("%w: exam_name is required", ErrInvalidInput)
	}
	if req.StartDate.IsZero() || req.EndDate.IsZero() {
		return fmt.Errorf("%w: start_date and end_date are required", ErrInvalidInput)
	}
	if req.StartDate.After(req.EndDate) {
		return fmt.Errorf("%w: start_date must be before end_date", ErrInvalidInput)
	}
	return nil
}

func (s *examService) validateExamScheduleCreate(req CreateExamScheduleRequest) error {
	if req.ExamID == uuid.Nil {
		return fmt.Errorf("%w: exam_id is required", ErrInvalidInput)
	}
	if req.SubjectID == uuid.Nil {
		return fmt.Errorf("%w: subject_id is required", ErrInvalidInput)
	}
	if req.Date.IsZero() {
		return fmt.Errorf("%w: date is required", ErrInvalidInput)
	}
	if req.MaxMarks <= 0 {
		return fmt.Errorf("%w: max_marks must be positive", ErrInvalidInput)
	}
	if req.PassingMarks < 0 {
		return fmt.Errorf("%w: passing_marks cannot be negative", ErrInvalidInput)
	}
	return nil
}

func (s *examService) validateExamResultCreate(req CreateExamResultRequest) error {
	if req.ExamID == uuid.Nil {
		return fmt.Errorf("%w: exam_id is required", ErrInvalidInput)
	}
	if req.EnrollmentID == uuid.Nil {
		return fmt.Errorf("%w: enrollment_id is required", ErrInvalidInput)
	}
	if req.SubjectID == uuid.Nil {
		return fmt.Errorf("%w: subject_id is required", ErrInvalidInput)
	}
	return nil
}

func (s *examService) validateExamGradeCreate(req CreateExamGradeRequest) error {
	if req.ExamID == uuid.Nil {
		return fmt.Errorf("%w: exam_id is required", ErrInvalidInput)
	}
	if req.GradeName == "" {
		return fmt.Errorf("%w: grade_name is required", ErrInvalidInput)
	}
	if req.MinMarks < 0 {
		return fmt.Errorf("%w: min_marks cannot be negative", ErrInvalidInput)
	}
	if req.MaxMarks <= req.MinMarks {
		return fmt.Errorf("%w: max_marks must be greater than min_marks", ErrInvalidInput)
	}
	return nil
}

// ---------------------------------------------------------------------
// Request structs with JSON tags (snake_case)
// ---------------------------------------------------------------------

type CreateExamRequest struct {
	AcademicYearID uuid.UUID  `json:"academic_year_id"`
	TermID         uuid.UUID  `json:"term_id"`
	ExamName       string     `json:"exam_name"`
	StartDate      time.Time  `json:"start_date"`
	EndDate        time.Time  `json:"end_date"`
	Description    string     `json:"description"`
	IsActive       bool       `json:"is_active"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateExamRequest struct {
	ExamID      uuid.UUID  `json:"exam_id"`
	TermID      uuid.UUID  `json:"term_id"`
	ExamName    string     `json:"exam_name"`
	StartDate   time.Time  `json:"start_date"`
	EndDate     time.Time  `json:"end_date"`
	Description string     `json:"description"`
	IsActive    bool       `json:"is_active"`
	UpdatedBy   *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateExamScheduleRequest struct {
	ExamID       uuid.UUID  `json:"exam_id"`
	SubjectID    uuid.UUID  `json:"subject_id"`
	Date         time.Time  `json:"date"`
	StartTime    *time.Time `json:"start_time,omitempty"`
	EndTime      *time.Time `json:"end_time,omitempty"`
	RoomID       *uuid.UUID `json:"room_id,omitempty"`
	MaxMarks     float64    `json:"max_marks"`
	PassingMarks float64    `json:"passing_marks"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy    *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateExamScheduleRequest struct {
	ScheduleID   uuid.UUID  `json:"schedule_id"`
	SubjectID    uuid.UUID  `json:"subject_id"`
	Date         time.Time  `json:"date"`
	StartTime    *time.Time `json:"start_time,omitempty"`
	EndTime      *time.Time `json:"end_time,omitempty"`
	RoomID       *uuid.UUID `json:"room_id,omitempty"`
	MaxMarks     float64    `json:"max_marks"`
	PassingMarks float64    `json:"passing_marks"`
	UpdatedBy    *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateExamResultRequest struct {
	ExamID        uuid.UUID  `json:"exam_id"`
	EnrollmentID  uuid.UUID  `json:"enrollment_id"`
	SubjectID     uuid.UUID  `json:"subject_id"`
	MarksObtained *float64   `json:"marks_obtained,omitempty"`
	Grade         string     `json:"grade,omitempty"`
	Remarks       string     `json:"remarks,omitempty"`
	EnteredBy     *uuid.UUID `json:"entered_by,omitempty"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
}

type UpdateExamResultRequest struct {
	ResultID      uuid.UUID  `json:"result_id"`
	MarksObtained *float64   `json:"marks_obtained,omitempty"`
	Grade         string     `json:"grade,omitempty"`
	Remarks       string     `json:"remarks,omitempty"`
	EnteredBy     *uuid.UUID `json:"entered_by,omitempty"`
	UpdatedBy     *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateExamGradeRequest struct {
	ExamID     uuid.UUID  `json:"exam_id"`
	GradeName  string     `json:"grade_name"`
	MinMarks   float64    `json:"min_marks"`
	MaxMarks   float64    `json:"max_marks"`
	GradePoint float64    `json:"grade_point"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
}

type UpdateExamGradeRequest struct {
	GradeID    uuid.UUID  `json:"grade_id"`
	GradeName  string     `json:"grade_name"`
	MinMarks   float64    `json:"min_marks"`
	MaxMarks   float64    `json:"max_marks"`
	GradePoint float64    `json:"grade_point"`
	UpdatedBy  *uuid.UUID `json:"updated_by,omitempty"`
}

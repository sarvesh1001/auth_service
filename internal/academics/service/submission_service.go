package service

import (
	"context"
	"database/sql"
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

// ---------------------------------------------------------------------
// Event types (matching outbox pattern)
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Service interface (updated – removed created_by/updated_by from requests)
// ---------------------------------------------------------------------

type SubmissionService interface {
	CreateSubmission(ctx context.Context, req CreateSubmissionRequest, idempotencyKey string) (*models.AssignmentSubmission, error)
	GetSubmissionByID(ctx context.Context, id uuid.UUID) (*models.AssignmentSubmission, error)
	GetSubmissionByAssignmentAndStudent(ctx context.Context, assignmentID, studentID uuid.UUID) (*models.AssignmentSubmission, error)
	ListSubmissions(ctx context.Context, filter repository.SubmissionFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.AssignmentSubmission, error)
	CountSubmissions(ctx context.Context, filter repository.SubmissionFilter) (int64, error)
	UpdateSubmission(ctx context.Context, req UpdateSubmissionRequest) (*models.AssignmentSubmission, error)
	DeleteSubmission(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	GradeSubmission(ctx context.Context, req GradeSubmissionRequest) (*models.AssignmentGrade, error)
	AddComment(ctx context.Context, req AddCommentRequest) (*models.AssignmentComment, error)
	GetCommentsBySubmission(ctx context.Context, submissionID uuid.UUID) ([]*models.AssignmentComment, error)
}

// ---------------------------------------------------------------------
// Request structs (no created_by/updated_by)
// ---------------------------------------------------------------------

type CreateSubmissionRequest struct {
	AssignmentID uuid.UUID `json:"assignment_id"`
	StudentID    uuid.UUID `json:"student_id"`
	FileURL      string    `json:"file_url,omitempty"`
	Remarks      string    `json:"remarks,omitempty"`
}

type UpdateSubmissionRequest struct {
	SubmissionID uuid.UUID `json:"submission_id"`
	FileURL      string    `json:"file_url,omitempty"`
	Remarks      string    `json:"remarks,omitempty"`
}

type GradeSubmissionRequest struct {
	SubmissionID uuid.UUID `json:"submission_id"`
	Marks        float64   `json:"marks"`
	Feedback     string    `json:"feedback,omitempty"`
	GradedBy     uuid.UUID `json:"graded_by"`
	Remarks      string    `json:"remarks,omitempty"`
}

type AddCommentRequest struct {
	SubmissionID uuid.UUID `json:"submission_id"`
	Comment      string    `json:"comment"`
	CommentBy    uuid.UUID `json:"comment_by"`
}

// ---------------------------------------------------------------------
// Service implementation
// ---------------------------------------------------------------------

type submissionService struct {
	repo            repository.SubmissionRepository
	assignmentRepo  repository.AssignmentRepository
	studentSvc      StudentService
	teacherSvc      TeacherService
	notificationSvc NotificationService
	pgClient        *client.PostgresClient
	logger          *zap.Logger

	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
}

func NewSubmissionService(
	repo repository.SubmissionRepository,
	assignmentRepo repository.AssignmentRepository,
	studentSvc StudentService,
	teacherSvc TeacherService,
	notificationSvc NotificationService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
) SubmissionService {
	return &submissionService{
		repo:             repo,
		assignmentRepo:   assignmentRepo,
		studentSvc:       studentSvc,
		teacherSvc:       teacherSvc,
		notificationSvc:  notificationSvc,
		pgClient:         pgClient,
		logger:           logger.Named("submission_service"),
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
	}
}

// ---------------------------------------------------------------------
// Helper: store outbox event for submission
// ---------------------------------------------------------------------

func (s *submissionService) storeOutboxEvent(ctx context.Context, tx *sql.Tx, eventType string, aggregateID uuid.UUID, payload interface{}) error {
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
		AggregateType: "submission",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         TopicStudent,
		Payload:       data,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	return s.outboxRepo.Store(ctx, tx, outboxEvent)
}

// ---------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------

func (s *submissionService) validateCreate(req CreateSubmissionRequest) error {
	if req.AssignmentID == uuid.Nil {
		return fmt.Errorf("%w: assignment_id required", ErrInvalidInput)
	}
	if req.StudentID == uuid.Nil {
		return fmt.Errorf("%w: student_id required", ErrInvalidInput)
	}
	return nil
}

func (s *submissionService) validateUpdate(req UpdateSubmissionRequest) error {
	if req.SubmissionID == uuid.Nil {
		return fmt.Errorf("%w: submission_id required", ErrInvalidInput)
	}
	return nil
}

// ---------------------------------------------------------------------
// CreateSubmission (with idempotency, audit, outbox)
// ---------------------------------------------------------------------

func (s *submissionService) CreateSubmission(ctx context.Context, req CreateSubmissionRequest, idempotencyKey string) (*models.AssignmentSubmission, error) {
	logger := s.logger.With(
		zap.String("method", "CreateSubmission"),
		zap.String("assignment_id", req.AssignmentID.String()),
		zap.String("student_id", req.StudentID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	if err := s.validateCreate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var existing models.AssignmentSubmission
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.SubmissionID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
		}
	}

	// Fetch assignment to get teacher and check due date
	assignment, err := s.assignmentRepo.GetByID(ctx, tx, req.AssignmentID)
	if err != nil {
		return nil, err
	}
	if assignment == nil {
		return nil, fmt.Errorf("%w: assignment %s", ErrNotFound, req.AssignmentID)
	}

	// Determine status: if due date passed -> "late", else "submitted"
	status := models.SubmissionSubmitted
	if time.Now().After(assignment.DueDate) {
		status = models.SubmissionLate
	}

	// Check if student already submitted
	existing, _ := s.repo.GetSubmissionByAssignmentAndStudent(ctx, tx, req.AssignmentID, req.StudentID)
	if existing != nil {
		return nil, fmt.Errorf("%w: student already submitted for this assignment", ErrDuplicate)
	}

	submission := &models.AssignmentSubmission{
		AssignmentID:   req.AssignmentID,
		StudentID:      req.StudentID,
		SubmissionDate: time.Now(),
		FileURL:        req.FileURL,
		Remarks:        req.Remarks,
		Status:         status,
		// CreatedBy removed – column no longer exists
	}

	if err := s.repo.CreateSubmission(ctx, tx, submission); err != nil {
		return nil, err
	}

	// Store idempotency key inside transaction
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, submission); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit log – use nil for actor (or could be extracted from context)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "create", "submission",
			&submission.SubmissionID, "user", nil, nil, nil, map[string]interface{}{
				"assignment_id": submission.AssignmentID,
				"student_id":    submission.StudentID,
				"status":        submission.Status,
			})
	}

	// Outbox event
	if err := s.storeOutboxEvent(ctx, tx, string(EventSubmissionCreated), submission.SubmissionID, submission); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Send notification to teacher (async) – no created_by available
	s.notifyTeacherOnSubmission(ctx, assignment, submission)

	logger.Info("submission created", zap.String("submission_id", submission.SubmissionID.String()))
	return submission, nil
}

// ---------------------------------------------------------------------
// Read‑only operations (no transaction needed)
// ---------------------------------------------------------------------

func (s *submissionService) GetSubmissionByID(ctx context.Context, id uuid.UUID) (*models.AssignmentSubmission, error) {
	sub, err := s.repo.GetSubmissionByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if sub == nil {
		return nil, fmt.Errorf("%w: submission %s", ErrNotFound, id)
	}
	return sub, nil
}

func (s *submissionService) GetSubmissionByAssignmentAndStudent(ctx context.Context, assignmentID, studentID uuid.UUID) (*models.AssignmentSubmission, error) {
	sub, err := s.repo.GetSubmissionByAssignmentAndStudent(ctx, s.pgClient.DB, assignmentID, studentID)
	if err != nil {
		return nil, err
	}
	if sub == nil {
		return nil, fmt.Errorf("%w: no submission for assignment %s by student %s", ErrNotFound, assignmentID, studentID)
	}
	return sub, nil
}

func (s *submissionService) ListSubmissions(ctx context.Context, filter repository.SubmissionFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.AssignmentSubmission, error) {
	return s.repo.ListSubmissions(ctx, s.pgClient.DB, filter, pagination, sort)
}

func (s *submissionService) CountSubmissions(ctx context.Context, filter repository.SubmissionFilter) (int64, error) {
	return s.repo.CountSubmissions(ctx, s.pgClient.DB, filter)
}

// ---------------------------------------------------------------------
// UpdateSubmission (with audit, outbox)
// ---------------------------------------------------------------------

func (s *submissionService) UpdateSubmission(ctx context.Context, req UpdateSubmissionRequest) (*models.AssignmentSubmission, error) {
	logger := s.logger.With(zap.String("method", "UpdateSubmission"), zap.String("submission_id", req.SubmissionID.String()))

	if err := s.validateUpdate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	existing, err := s.repo.GetSubmissionByID(ctx, tx, req.SubmissionID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: submission %s", ErrNotFound, req.SubmissionID)
	}

	// Update fields
	existing.FileURL = req.FileURL
	existing.Remarks = req.Remarks
	existing.SubmissionDate = time.Now() // resubmission date

	if err := s.repo.UpdateSubmission(ctx, tx, existing); err != nil {
		return nil, err
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "submission",
			&req.SubmissionID, "user", nil, nil, nil, map[string]interface{}{
				"file_url": existing.FileURL,
				"remarks":  existing.Remarks,
			})
	}

	// Outbox event
	if err := s.storeOutboxEvent(ctx, tx, string(EventSubmissionUpdated), existing.SubmissionID, existing); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("submission updated")
	return existing, nil
}

// ---------------------------------------------------------------------
// DeleteSubmission (hard delete, deletedBy ignored as table has no such column)
// ---------------------------------------------------------------------

func (s *submissionService) DeleteSubmission(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteSubmission"), zap.String("submission_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteSubmission(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete", "submission",
			&id, "user", deletedBy, nil, nil, nil)
	}

	if err := s.storeOutboxEvent(ctx, tx, string(EventSubmissionDeleted), id, map[string]interface{}{
		"submission_id": id,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("submission deleted")
	return nil
}

// ---------------------------------------------------------------------
// GradeSubmission (with audit, outbox)
// ---------------------------------------------------------------------

func (s *submissionService) GradeSubmission(ctx context.Context, req GradeSubmissionRequest) (*models.AssignmentGrade, error) {
	logger := s.logger.With(
		zap.String("method", "GradeSubmission"),
		zap.String("submission_id", req.SubmissionID.String()),
	)

	if req.SubmissionID == uuid.Nil {
		return nil, fmt.Errorf("%w: submission_id required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Get submission with assignment details
	submission, err := s.repo.GetSubmissionByID(ctx, tx, req.SubmissionID)
	if err != nil {
		return nil, err
	}
	if submission == nil {
		return nil, fmt.Errorf("%w: submission %s", ErrNotFound, req.SubmissionID)
	}

	// Ensure not already graded (optional)
	if submission.Status == models.SubmissionGraded {
		return nil, fmt.Errorf("submission already graded")
	}

	// Update submission with marks and feedback
	submission.MarksObtained = &req.Marks
	submission.Feedback = req.Feedback
	submission.Status = models.SubmissionGraded
	submission.GradedBy = &req.GradedBy
	now := time.Now()
	submission.GradedAt = &now

	if err := s.repo.UpdateSubmission(ctx, tx, submission); err != nil {
		return nil, err
	}

	// Create grade record – no created_by column
	grade := &models.AssignmentGrade{
		SubmissionID: req.SubmissionID,
		Marks:        req.Marks,
		GradedBy:     req.GradedBy,
		GradedAt:     now,
		Remarks:      req.Remarks,
	}
	if err := s.repo.CreateGrade(ctx, tx, grade); err != nil {
		return nil, err
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "grade", "submission",
			&submission.SubmissionID, "user", &req.GradedBy, nil, nil, map[string]interface{}{
				"marks":    req.Marks,
				"feedback": req.Feedback,
			})
	}

	// Outbox event
	if err := s.storeOutboxEvent(ctx, tx, string(EventSubmissionGraded), submission.SubmissionID, map[string]interface{}{
		"submission_id": submission.SubmissionID,
		"assignment_id": submission.AssignmentID,
		"student_id":    submission.StudentID,
		"marks":         req.Marks,
		"feedback":      req.Feedback,
		"graded_by":     req.GradedBy,
	}); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Notify student about grade
	s.notifyStudentOnGrade(ctx, submission)

	logger.Info("submission graded", zap.Float64("marks", req.Marks))
	return grade, nil
}

// ---------------------------------------------------------------------
// AddComment (with audit, outbox)
// ---------------------------------------------------------------------

func (s *submissionService) AddComment(ctx context.Context, req AddCommentRequest) (*models.AssignmentComment, error) {
	logger := s.logger.With(
		zap.String("method", "AddComment"),
		zap.String("submission_id", req.SubmissionID.String()),
	)

	if req.SubmissionID == uuid.Nil {
		return nil, fmt.Errorf("%w: submission_id required", ErrInvalidInput)
	}
	if req.Comment == "" {
		return nil, fmt.Errorf("%w: comment cannot be empty", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Verify submission exists
	sub, err := s.repo.GetSubmissionByID(ctx, tx, req.SubmissionID)
	if err != nil || sub == nil {
		return nil, fmt.Errorf("%w: submission %s", ErrNotFound, req.SubmissionID)
	}

	comment := &models.AssignmentComment{
		SubmissionID: req.SubmissionID,
		CommentBy:    req.CommentBy,
		Comment:      req.Comment,
		// CreatedBy removed
	}
	if err := s.repo.AddComment(ctx, tx, comment); err != nil {
		return nil, err
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "add_comment", "submission_comment",
			&comment.CommentID, "user", &req.CommentBy, nil, nil, map[string]interface{}{
				"submission_id": req.SubmissionID,
				"comment":       req.Comment,
			})
	}

	// Outbox event
	if err := s.storeOutboxEvent(ctx, tx, string(EventSubmissionCommentAdded), comment.CommentID, map[string]interface{}{
		"submission_id": req.SubmissionID,
		"comment_id":    comment.CommentID,
		"comment_by":    req.CommentBy,
		"comment":       req.Comment,
	}); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Notify student about comment
	s.notifyStudentOnComment(ctx, sub, comment)

	logger.Info("comment added")
	return comment, nil
}

// ---------------------------------------------------------------------
// GetCommentsBySubmission (read-only)
// ---------------------------------------------------------------------

func (s *submissionService) GetCommentsBySubmission(ctx context.Context, submissionID uuid.UUID) ([]*models.AssignmentComment, error) {
	return s.repo.GetCommentsBySubmission(ctx, s.pgClient.DB, submissionID)
}

// ---------------------------------------------------------------------
// Notification helpers (no created_by passed)
// ---------------------------------------------------------------------

func (s *submissionService) notifyTeacherOnSubmission(ctx context.Context, assignment *models.Assignment, submission *models.AssignmentSubmission) {
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		teacher, err := s.teacherSvc.GetByID(notifyCtx, assignment.TeacherID)
		if err != nil || teacher == nil {
			s.logger.Error("failed to fetch teacher for notification", zap.String("teacher_id", assignment.TeacherID.String()), zap.Error(err))
			return
		}

		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
			Title:     fmt.Sprintf("New Submission for %s", assignment.Title),
			Message:   fmt.Sprintf("Student submitted assignment '%s'.", assignment.Title),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetUser,
					TargetEntityID: teacher.UserID,
				},
			},
			CreatedBy: nil, // no actor info available
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "submission."+submission.SubmissionID.String()); err != nil {
			s.logger.Error("failed to send teacher notification for submission", zap.Error(err))
		}
	}()
}

func (s *submissionService) notifyStudentOnGrade(ctx context.Context, submission *models.AssignmentSubmission) {
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		student, err := s.studentSvc.GetByID(notifyCtx, submission.StudentID)
		if err != nil || student == nil {
			s.logger.Error("failed to fetch student for notification", zap.String("student_id", submission.StudentID.String()), zap.Error(err))
			return
		}

		assignment, err := s.assignmentRepo.GetByID(notifyCtx, s.pgClient.DB, submission.AssignmentID)
		if err != nil || assignment == nil {
			s.logger.Error("failed to fetch assignment for notification", zap.String("assignment_id", submission.AssignmentID.String()), zap.Error(err))
			return
		}

		marks := ""
		if submission.MarksObtained != nil {
			marks = fmt.Sprintf(" Marks: %.2f", *submission.MarksObtained)
		}

		notifReq := CreateNotificationRequest{
			CompanyID: student.CompanyID,
			Title:     fmt.Sprintf("Assignment Graded: %s", assignment.Title),
			Message:   fmt.Sprintf("Your submission for '%s' has been graded.%s", assignment.Title, marks),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetStudent,
					TargetEntityID: student.StudentID,
				},
			},
			CreatedBy: submission.GradedBy, // graded_by is the actor
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "submission.grade."+submission.SubmissionID.String()); err != nil {
			s.logger.Error("failed to send student notification for grade", zap.Error(err))
		}
	}()
}

func (s *submissionService) notifyStudentOnComment(ctx context.Context, submission *models.AssignmentSubmission, comment *models.AssignmentComment) {
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		student, err := s.studentSvc.GetByID(notifyCtx, submission.StudentID)
		if err != nil || student == nil {
			s.logger.Error("failed to fetch student for comment notification", zap.String("student_id", submission.StudentID.String()), zap.Error(err))
			return
		}

		notifReq := CreateNotificationRequest{
			CompanyID: student.CompanyID,
			Title:     "New Comment on Your Submission",
			Message:   fmt.Sprintf("A new comment was added: %s", comment.Comment),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityLow,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetStudent,
					TargetEntityID: student.StudentID,
				},
			},
			CreatedBy: &comment.CommentBy, // comment_by is the actor
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "submission.comment."+comment.CommentID.String()); err != nil {
			s.logger.Error("failed to send student notification for comment", zap.Error(err))
		}
	}()
}

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

// AttendanceService defines the public methods for attendance operations.
type AttendanceService interface {
	// MarkAttendance creates or updates a single attendance record.
	MarkAttendance(ctx context.Context, req MarkAttendanceRequest, idempotencyKey string) (*models.StudentAttendance, error)

	// BulkMarkAttendance processes multiple attendance records in one transaction.
	BulkMarkAttendance(ctx context.Context, req BulkMarkAttendanceRequest) ([]*models.StudentAttendance, error)

	// GetAttendanceByID returns a single attendance record.
	GetAttendanceByID(ctx context.Context, id uuid.UUID) (*models.StudentAttendance, error)

	// ListAttendance returns attendance records matching the filter.
	ListAttendance(ctx context.Context, filter ListAttendanceRequest) ([]*models.StudentAttendance, int64, error)

	// DeleteAttendance soft-deletes an attendance record.
	DeleteAttendance(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	// GetSummary returns the attendance summary for a student.
	GetSummary(ctx context.Context, studentID, academicYearID uuid.UUID, termID *uuid.UUID) (*AttendanceSummaryResponse, error)

	// RecalculateSummary forces recalculation of a student's summary.
	RecalculateSummary(ctx context.Context, studentID, academicYearID uuid.UUID, termID *uuid.UUID) error

	// BulkRecalcSummaries recalculates summaries for multiple students.
	BulkRecalcSummaries(ctx context.Context, studentIDs []uuid.UUID, academicYearID uuid.UUID, termID *uuid.UUID) error

	// CreateExemption creates an attendance exemption.
	CreateExemption(ctx context.Context, req CreateAttendanceExemptionRequest, idempotencyKey string) (*models.StudentAttendanceExemption, error)

	// UpdateExemption updates an existing exemption.
	UpdateExemption(ctx context.Context, req UpdateAttendanceExemptionRequest) (*models.StudentAttendanceExemption, error)

	// DeleteExemption deletes an exemption.
	DeleteExemption(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	// ListExemptions returns exemptions for a student or date range.
	ListExemptions(ctx context.Context, studentID *uuid.UUID, fromDate, toDate *time.Time, limit, offset int) ([]*models.StudentAttendanceExemption, error)
}

type attendanceService struct {
	repo             repository.AttendanceRepository
	enrollmentRepo   repository.EnrollmentRepository
	studentRepo      repository.StudentRepository // Added
	idempotencyStore IdempotencyStore
	auditLogger      AuditLogger
	outboxStore      OutboxStore
	eventPublisher   EventPublisher
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	notificationSvc  NotificationService
}

// NewAttendanceService creates a new attendance service.
func NewAttendanceService(
	repo repository.AttendanceRepository,
	enrollmentRepo repository.EnrollmentRepository,
	studentRepo repository.StudentRepository, // Added
	idempotencyStore IdempotencyStore,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationSvc NotificationService,
) AttendanceService {
	return &attendanceService{
		repo:             repo,
		enrollmentRepo:   enrollmentRepo,
		studentRepo:      studentRepo,
		idempotencyStore: idempotencyStore,
		auditLogger:      auditLogger,
		outboxStore:      outboxStore,
		eventPublisher:   eventPublisher,
		pgClient:         pgClient,
		logger:           logger.Named("attendance_service"),
		notificationSvc:  notificationSvc,
	}
}

// validateAttendanceInput checks required fields.
func (s *attendanceService) validateAttendanceInput(req MarkAttendanceRequest) error {
	if req.EnrollmentID == uuid.Nil {
		return fmt.Errorf("%w: enrollment_id is required", ErrInvalidInput)
	}
	if req.Date.IsZero() {
		return fmt.Errorf("%w: date is required", ErrInvalidInput)
	}
	if req.Status == "" {
		return fmt.Errorf("%w: status is required", ErrInvalidInput)
	}
	if !models.IsValidAttendanceStatus(string(req.Status)) {
		return fmt.Errorf("%w: invalid status %q", ErrInvalidInput, req.Status)
	}
	return nil
}

// createAttendanceNotification sends a notification for the given attendance record.
// It runs asynchronously after the main transaction commits.
func (s *attendanceService) createAttendanceNotification(ctx context.Context, enrollmentID uuid.UUID, date time.Time, status models.AttendanceStatus, markedBy *uuid.UUID) {
	// Fetch enrollment to get student ID
	enrollment, err := s.enrollmentRepo.GetByIDUnsafe(ctx, s.pgClient.DB, enrollmentID)
	if err != nil {
		s.logger.Error("failed to fetch enrollment for notification", zap.String("enrollment_id", enrollmentID.String()), zap.Error(err))
		return
	}
	if enrollment == nil {
		s.logger.Error("enrollment not found for notification", zap.String("enrollment_id", enrollmentID.String()))
		return
	}

	// Fetch student to get company ID and other details
	student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, enrollment.StudentID)
	if err != nil {
		s.logger.Error("failed to fetch student for notification", zap.String("student_id", enrollment.StudentID.String()), zap.Error(err))
		return
	}
	if student == nil {
		s.logger.Error("student not found for notification", zap.String("student_id", enrollment.StudentID.String()))
		return
	}

	var title, message string
	switch status {
	case models.StatusAbsent:
		title = "Attendance Alert: Absent"
		message = fmt.Sprintf("Student was marked absent on %s", date.Format("2006-01-02"))
	case models.StatusLate:
		title = "Attendance Alert: Late Arrival"
		message = fmt.Sprintf("Student was marked late on %s", date.Format("2006-01-02"))
	default:
		return // no notification needed
	}

	// Build notification request
	notifReq := CreateNotificationRequest{
		CompanyID: student.CompanyID,
		Title:     title,
		Message:   message,
		Type:      models.NotificationTypeAlert,
		Priority:  models.PriorityNormal,
		ExpiresAt: nil,
		Targets: []NotificationTargetInput{
			{
				TargetType:     models.TargetStudent,
				TargetEntityID: enrollment.StudentID,
			},
		},
		CreatedBy: markedBy,
	}

	// Create notification (its own transaction)
	_, err = s.notificationSvc.Create(ctx, notifReq, "")
	if err != nil {
		s.logger.Error("failed to create attendance notification",
			zap.String("enrollment_id", enrollmentID.String()),
			zap.String("status", string(status)),
			zap.Error(err))
	}
}

// MarkAttendance implements AttendanceService.
func (s *attendanceService) MarkAttendance(ctx context.Context, req MarkAttendanceRequest, idempotencyKey string) (*models.StudentAttendance, error) {
	logger := s.logger.With(
		zap.String("method", "MarkAttendance"),
		zap.String("enrollment_id", req.EnrollmentID.String()),
		zap.Time("date", req.Date),
		zap.String("status", string(req.Status)),
	)

	if err := s.validateAttendanceInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var attendance models.StudentAttendance
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &attendance); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &attendance, nil
		}
	}

	attendance := &models.StudentAttendance{
		EnrollmentID:   req.EnrollmentID,
		AttendanceDate: req.Date,
		Status:         req.Status,
		MarkedBy:       req.MarkedBy,
		Remarks:        req.Remarks,
		CreatedBy:      req.CreatedBy,
	}

	if err := s.repo.Upsert(ctx, tx, attendance); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, attendance); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit
	if err := s.auditLogger.Log(ctx, tx, "UPSERT", attendance.AttendanceID, nil, attendance, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox event
	if err := s.outboxStore.Store(ctx, tx, string(EventAttendanceMarked), attendance); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// After commit, create notification asynchronously
	go s.createAttendanceNotification(context.Background(), req.EnrollmentID, req.Date, req.Status, req.MarkedBy)

	logger.Info("attendance marked", zap.String("attendance_id", attendance.AttendanceID.String()))
	return attendance, nil
}

// BulkMarkAttendance implements AttendanceService.
func (s *attendanceService) BulkMarkAttendance(ctx context.Context, req BulkMarkAttendanceRequest) ([]*models.StudentAttendance, error) {
	if len(req.Attendances) == 0 {
		return nil, nil
	}
	logger := s.logger.With(zap.String("method", "BulkMarkAttendance"), zap.Int("count", len(req.Attendances)))

	// Validate each request
	for i, r := range req.Attendances {
		if err := s.validateAttendanceInput(r); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	attendances := make([]*models.StudentAttendance, 0, len(req.Attendances))
	for _, r := range req.Attendances {
		a := &models.StudentAttendance{
			EnrollmentID:   r.EnrollmentID,
			AttendanceDate: r.Date,
			Status:         r.Status,
			MarkedBy:       r.MarkedBy,
			Remarks:        r.Remarks,
			CreatedBy:      r.CreatedBy,
		}
		attendances = append(attendances, a)
	}

	if err := s.repo.BulkUpsert(ctx, tx, attendances); err != nil {
		return nil, err
	}

	// Audit (could be batched, but we'll do individually for simplicity)
	for _, a := range attendances {
		if err := s.auditLogger.Log(ctx, tx, "UPSERT", a.AttendanceID, nil, a, req.CreatedBy); err != nil {
			logger.Error("audit log failed", zap.String("attendance_id", a.AttendanceID.String()), zap.Error(err))
		}
	}

	// Outbox event with summary payload
	if err := s.outboxStore.Store(ctx, tx, string(EventAttendanceBulkMarked), map[string]interface{}{
		"count": len(attendances),
		"enrollment_ids": func() []uuid.UUID {
			ids := make([]uuid.UUID, len(attendances))
			for i, a := range attendances {
				ids[i] = a.EnrollmentID
			}
			return ids
		}(),
		"created_by": req.CreatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// After commit, create notifications asynchronously
	for _, a := range attendances {
		if a.Status == models.StatusAbsent || a.Status == models.StatusLate {
			go s.createAttendanceNotification(context.Background(), a.EnrollmentID, a.AttendanceDate, a.Status, a.MarkedBy)
		}
	}

	logger.Info("bulk attendance marked", zap.Int("count", len(attendances)))
	return attendances, nil
}

func (s *attendanceService) GetAttendanceByID(ctx context.Context, id uuid.UUID) (*models.StudentAttendance, error) {
	a, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, fmt.Errorf("%w: attendance %s", ErrNotFound, id)
	}
	return a, nil
}

// ListAttendance implements AttendanceService.
func (s *attendanceService) ListAttendance(ctx context.Context, filter ListAttendanceRequest) ([]*models.StudentAttendance, int64, error) {
	// Build repository filter
	repoFilter := repository.AttendanceFilter{
		EnrollmentID:   filter.EnrollmentID,
		StudentID:      filter.StudentID,
		SectionID:      filter.SectionID,
		TermID:         filter.TermID,
		AcademicYearID: filter.AcademicYearID,
		FromDate:       filter.FromDate,
		ToDate:         filter.ToDate,
		Status:         filter.Status,
		MarkedBy:       filter.MarkedBy,
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	pag := repository.Pagination{Limit: limit, Offset: offset}

	sortField := filter.SortField
	if sortField == "" {
		sortField = "attendance_date"
	}
	sortDir := filter.SortDirection
	if sortDir == "" {
		sortDir = "DESC"
	}
	srt := repository.Sort{Field: sortField, Direction: sortDir}

	attendances, err := s.repo.List(ctx, s.pgClient.DB, repoFilter, pag, srt)
	if err != nil {
		return nil, 0, err
	}

	total, err := s.repo.Count(ctx, s.pgClient.DB, repoFilter)
	if err != nil {
		return nil, 0, err
	}

	return attendances, total, nil
}

// DeleteAttendance implements AttendanceService.
func (s *attendanceService) DeleteAttendance(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteAttendance"), zap.String("attendance_id", id.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// First, get the attendance record for audit
	a, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if a == nil {
		return fmt.Errorf("%w: attendance %s", ErrNotFound, id)
	}

	if err := s.repo.Delete(ctx, tx, id); err != nil {
		return err
	}

	// Audit
	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, a, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventAttendanceMarked)+".deleted", map[string]interface{}{
		"attendance_id": id,
		"deleted_by":    deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("attendance deleted")
	return nil
}

// GetSummary implements AttendanceService.
func (s *attendanceService) GetSummary(ctx context.Context, studentID, academicYearID uuid.UUID, termID *uuid.UUID) (*AttendanceSummaryResponse, error) {
	summary, err := s.repo.GetSummary(ctx, s.pgClient.DB, studentID, academicYearID, termID)
	if err != nil {
		return nil, err
	}
	if summary == nil {
		return nil, fmt.Errorf("%w: attendance summary not found", ErrNotFound)
	}

	return &AttendanceSummaryResponse{
		SummaryID:            summary.SummaryID,
		StudentID:            summary.StudentID,
		AcademicYearID:       summary.AcademicYearID,
		TermID:               summary.TermID,
		TotalPresent:         summary.TotalPresent,
		TotalAbsent:          summary.TotalAbsent,
		TotalLate:            summary.TotalLate,
		TotalHalfDay:         summary.TotalHalfDay,
		TotalWorkingDays:     summary.TotalWorkingDays,
		AttendancePercentage: summary.AttendancePercentage,
		CreatedAt:            summary.CreatedAt,
		UpdatedAt:            summary.UpdatedAt,
	}, nil
}

// RecalculateSummary implements AttendanceService.
func (s *attendanceService) RecalculateSummary(ctx context.Context, studentID, academicYearID uuid.UUID, termID *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "RecalculateSummary"),
		zap.String("student_id", studentID.String()),
		zap.String("academic_year_id", academicYearID.String()),
	)
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.RecalculateSummary(ctx, tx, studentID, academicYearID, termID); err != nil {
		return err
	}

	// Outbox event for summary update
	if err := s.outboxStore.Store(ctx, tx, string(EventAttendanceSummaryUpdated), map[string]interface{}{
		"student_id":       studentID,
		"academic_year_id": academicYearID,
		"term_id":          termID,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("summary recalculated")
	return nil
}

// BulkRecalcSummaries implements AttendanceService.
func (s *attendanceService) BulkRecalcSummaries(ctx context.Context, studentIDs []uuid.UUID, academicYearID uuid.UUID, termID *uuid.UUID) error {
	if len(studentIDs) == 0 {
		return nil
	}
	logger := s.logger.With(
		zap.String("method", "BulkRecalcSummaries"),
		zap.Int("count", len(studentIDs)),
		zap.String("academic_year_id", academicYearID.String()),
	)
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.BulkRecalcSummaries(ctx, tx, studentIDs, academicYearID, termID); err != nil {
		return err
	}

	// Outbox event
	if err := s.outboxStore.Store(ctx, tx, string(EventAttendanceSummaryUpdated), map[string]interface{}{
		"student_ids":      studentIDs,
		"academic_year_id": academicYearID,
		"term_id":          termID,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("bulk summaries recalculated")
	return nil
}

// CreateExemption implements AttendanceService.
func (s *attendanceService) CreateExemption(ctx context.Context, req CreateAttendanceExemptionRequest, idempotencyKey string) (*models.StudentAttendanceExemption, error) {
	logger := s.logger.With(
		zap.String("method", "CreateExemption"),
		zap.String("student_id", req.StudentID.String()),
		zap.Time("from", req.FromDate),
		zap.Time("to", req.ToDate),
	)

	if req.StudentID == uuid.Nil {
		return nil, fmt.Errorf("%w: student_id is required", ErrInvalidInput)
	}
	if req.FromDate.IsZero() || req.ToDate.IsZero() {
		return nil, fmt.Errorf("%w: from_date and to_date are required", ErrInvalidInput)
	}
	if req.FromDate.After(req.ToDate) {
		return nil, fmt.Errorf("%w: from_date must be before to_date", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var ex models.StudentAttendanceExemption
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &ex); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &ex, nil
		}
	}

	exemption := &models.StudentAttendanceExemption{
		StudentID:  req.StudentID,
		FromDate:   req.FromDate,
		ToDate:     req.ToDate,
		Reason:     req.Reason,
		ApprovedBy: req.ApprovedBy,
		CreatedBy:  req.CreatedBy,
	}

	if err := s.repo.CreateExemption(ctx, tx, exemption); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, exemption); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if err := s.auditLogger.Log(ctx, tx, "CREATE", exemption.ExemptionID, nil, exemption, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventAttendanceExemptionCreated), exemption); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("exemption created", zap.String("exemption_id", exemption.ExemptionID.String()))
	return exemption, nil
}

// UpdateExemption implements AttendanceService.
func (s *attendanceService) UpdateExemption(ctx context.Context, req UpdateAttendanceExemptionRequest) (*models.StudentAttendanceExemption, error) {
	logger := s.logger.With(zap.String("method", "UpdateExemption"), zap.String("exemption_id", req.ExemptionID.String()))

	if req.ExemptionID == uuid.Nil {
		return nil, fmt.Errorf("%w: exemption_id is required", ErrInvalidInput)
	}
	if req.FromDate.IsZero() || req.ToDate.IsZero() {
		return nil, fmt.Errorf("%w: from_date and to_date are required", ErrInvalidInput)
	}
	if req.FromDate.After(req.ToDate) {
		return nil, fmt.Errorf("%w: from_date must be before to_date", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Get existing for audit
	existing, err := s.repo.GetExemptionByID(ctx, tx, req.ExemptionID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: exemption %s", ErrNotFound, req.ExemptionID)
	}

	existing.FromDate = req.FromDate
	existing.ToDate = req.ToDate
	existing.Reason = req.Reason
	existing.ApprovedBy = req.ApprovedBy

	if err := s.repo.UpdateExemption(ctx, tx, existing); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE", existing.ExemptionID, existing, existing, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventAttendanceExemptionUpdated), existing); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("exemption updated")
	return existing, nil
}

// DeleteExemption implements AttendanceService.
func (s *attendanceService) DeleteExemption(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteExemption"), zap.String("exemption_id", id.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Get for audit
	ex, err := s.repo.GetExemptionByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if ex == nil {
		return fmt.Errorf("%w: exemption %s", ErrNotFound, id)
	}

	if err := s.repo.DeleteExemption(ctx, tx, id); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, ex, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventAttendanceExemptionDeleted), map[string]interface{}{
		"exemption_id": id,
		"deleted_by":   deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("exemption deleted")
	return nil
}

// ListExemptions implements AttendanceService.
func (s *attendanceService) ListExemptions(ctx context.Context, studentID *uuid.UUID, fromDate, toDate *time.Time, limit, offset int) ([]*models.StudentAttendanceExemption, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	pag := repository.Pagination{Limit: limit, Offset: offset}
	return s.repo.ListExemptions(ctx, s.pgClient.DB, studentID, fromDate, toDate, pag)
}

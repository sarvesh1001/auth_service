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

type AttendanceService interface {
	MarkAttendance(ctx context.Context, req MarkAttendanceRequest, idempotencyKey string) (*models.StudentAttendance, error)
	BulkMarkAttendance(ctx context.Context, req BulkMarkAttendanceRequest) ([]*models.StudentAttendance, error)
	GetAttendanceByID(ctx context.Context, id uuid.UUID) (*models.StudentAttendance, error)
	ListAttendance(ctx context.Context, filter ListAttendanceRequest) ([]*models.StudentAttendance, int64, error)
	DeleteAttendance(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	GetSummary(ctx context.Context, studentID, academicYearID uuid.UUID, termID *uuid.UUID) (*AttendanceSummaryResponse, error)
	RecalculateSummary(ctx context.Context, studentID, academicYearID uuid.UUID, termID *uuid.UUID) error
	BulkRecalcSummaries(ctx context.Context, studentIDs []uuid.UUID, academicYearID uuid.UUID, termID *uuid.UUID) error
	CreateExemption(ctx context.Context, req CreateAttendanceExemptionRequest, idempotencyKey string) (*models.StudentAttendanceExemption, error)
	UpdateExemption(ctx context.Context, req UpdateAttendanceExemptionRequest) (*models.StudentAttendanceExemption, error)
	DeleteExemption(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	ListExemptions(ctx context.Context, studentID *uuid.UUID, fromDate, toDate *time.Time, limit, offset int) ([]*models.StudentAttendanceExemption, error)
	MarkPeriodAttendance(ctx context.Context, req MarkPeriodAttendanceRequest) (*models.StudentSessionAttendance, error)
	MarkPeriodAttendanceBiometric(ctx context.Context, req BiometricPunchRequest) (*models.StudentSessionAttendance, error)
	GetPeriodAttendanceBySession(ctx context.Context, sessionID uuid.UUID) ([]*models.StudentSessionAttendance, error)
}

type attendanceService struct {
	repo                  repository.AttendanceRepository
	enrollmentRepo        repository.EnrollmentRepository
	studentRepo           repository.StudentRepository
	pgClient              *client.PostgresClient
	logger                *zap.Logger
	notificationSvc       NotificationService
	idempotencyStore      idempotency.Store
	auditService          *audit.AuditService
	outboxRepo            outbox.Repository
	academicSessionRepo   repository.AcademicSessionRepository
	studentSessionAttRepo repository.StudentSessionAttendanceRepository
	attendanceSessionRepo repository.AttendanceSessionRepository
	biometricMappingRepo  repository.StudentBiometricMappingRepository
}

func NewAttendanceService(
	repo repository.AttendanceRepository,
	enrollmentRepo repository.EnrollmentRepository,
	studentRepo repository.StudentRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationSvc NotificationService,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	academicSessionRepo repository.AcademicSessionRepository,
	studentSessionAttRepo repository.StudentSessionAttendanceRepository,
	attendanceSessionRepo repository.AttendanceSessionRepository,
	biometricMappingRepo repository.StudentBiometricMappingRepository,
) AttendanceService {
	return &attendanceService{
		repo:                  repo,
		enrollmentRepo:        enrollmentRepo,
		studentRepo:           studentRepo,
		pgClient:              pgClient,
		logger:                logger.Named("attendance_service"),
		notificationSvc:       notificationSvc,
		idempotencyStore:      idempotencyStore,
		auditService:          auditService,
		outboxRepo:            outboxRepo,
		academicSessionRepo:   academicSessionRepo,
		studentSessionAttRepo: studentSessionAttRepo,
		attendanceSessionRepo: attendanceSessionRepo,
		biometricMappingRepo:  biometricMappingRepo,
	}
}

func isAutoSource(source models.AttendanceSourceType) bool {
	return source == models.SourceBiometric
}

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

// storeOutboxEvent stores an outbox event with the given topic.
func (s *attendanceService) storeOutboxEvent(ctx context.Context, tx *sql.Tx, eventType string, aggregateID uuid.UUID, topic string, payload interface{}) error {
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
		AggregateType: "attendance",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         topic, // <-- NEW
		Payload:       data,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	return s.outboxRepo.Store(ctx, tx, outboxEvent)
}

func (s *attendanceService) MarkAttendance(ctx context.Context, req MarkAttendanceRequest, idempotencyKey string) (*models.StudentAttendance, error) {
	logger := s.logger.With(
		zap.String("method", "MarkAttendance"),
		zap.String("enrollment_id", req.EnrollmentID.String()),
		zap.Time("date", req.Date),
		zap.String("status", string(req.Status)),
		zap.String("idempotency_key", idempotencyKey),
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
		var existing models.StudentAttendance
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.AttendanceID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
		}
	}

	attendance := &models.StudentAttendance{
		EnrollmentID:   req.EnrollmentID,
		AttendanceDate: req.Date,
		Status:         req.Status,
		MarkedBy:       req.MarkedBy,
		Remarks:        req.Remarks,
		CreatedBy:      req.CreatedBy,
		SourceType:     req.SourceType,
		DeviceID:       req.DeviceID,
	}

	if err := s.repo.Upsert(ctx, tx, attendance); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, attendance); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "upsert", "attendance",
			&attendance.AttendanceID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"enrollment_id": attendance.EnrollmentID,
				"date":          attendance.AttendanceDate,
				"status":        attendance.Status,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, string(EventAttendanceMarked), attendance.AttendanceID, TopicAttendance, attendance); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	go s.createAttendanceNotification(context.Background(), req.EnrollmentID, req.Date, req.Status, req.MarkedBy)

	logger.Info("attendance marked", zap.String("attendance_id", attendance.AttendanceID.String()))
	return attendance, nil
}

func (s *attendanceService) BulkMarkAttendance(ctx context.Context, req BulkMarkAttendanceRequest) ([]*models.StudentAttendance, error) {
	if len(req.Attendances) == 0 {
		return nil, nil
	}

	logger := s.logger.With(zap.String("method", "BulkMarkAttendance"), zap.Int("count", len(req.Attendances)))

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
			SourceType:     r.SourceType,
			DeviceID:       r.DeviceID,
		}
		attendances = append(attendances, a)
	}

	if err := s.repo.BulkUpsert(ctx, tx, attendances); err != nil {
		return nil, err
	}

	for _, a := range attendances {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "academics", "bulk_upsert", "attendance",
				&a.AttendanceID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
					"enrollment_id": a.EnrollmentID,
					"date":          a.AttendanceDate,
					"status":        a.Status,
				})
		}
		if err := s.storeOutboxEvent(ctx, tx, string(EventAttendanceBulkMarked), a.AttendanceID, TopicAttendance, a); err != nil {
			return nil, fmt.Errorf("outbox store for %s: %w", a.AttendanceID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

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

func (s *attendanceService) ListAttendance(ctx context.Context, filter ListAttendanceRequest) ([]*models.StudentAttendance, int64, error) {
	var statusPtr *string
	if filter.Status != nil {
		s := string(*filter.Status)
		statusPtr = &s
	}

	repoFilter := repository.AttendanceFilter{
		EnrollmentID:   filter.EnrollmentID,
		StudentID:      filter.StudentID,
		SectionID:      filter.SectionID,
		TermID:         filter.TermID,
		AcademicYearID: filter.AcademicYearID,
		FromDate:       filter.FromDate,
		ToDate:         filter.ToDate,
		Status:         statusPtr,
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

func (s *attendanceService) DeleteAttendance(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteAttendance"), zap.String("attendance_id", id.String()))

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
		return fmt.Errorf("%w: attendance %s", ErrNotFound, id)
	}

	if err := s.repo.Delete(ctx, tx, id); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete", "attendance",
			&id, "user", deletedBy, nil, nil, nil)
	}

	// Use a custom event type or reuse attendance deleted event; keep topic as attendance
	if err := s.storeOutboxEvent(ctx, tx, string(EventAttendanceMarked)+".deleted", id, TopicAttendance, map[string]interface{}{
		"attendance_id": id,
		"deleted_by":    deletedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("attendance deleted")
	return nil
}

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

	if err := s.storeOutboxEvent(ctx, tx, string(EventAttendanceSummaryUpdated), studentID, TopicAttendance, map[string]interface{}{
		"student_id":       studentID,
		"academic_year_id": academicYearID,
		"term_id":          termID,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("summary recalculated")
	return nil
}

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

	if err := s.storeOutboxEvent(ctx, tx, string(EventAttendanceSummaryUpdated), uuid.Nil, TopicAttendance, map[string]interface{}{
		"student_ids":      studentIDs,
		"academic_year_id": academicYearID,
		"term_id":          termID,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("bulk summaries recalculated")
	return nil
}

func (s *attendanceService) CreateExemption(ctx context.Context, req CreateAttendanceExemptionRequest, idempotencyKey string) (*models.StudentAttendanceExemption, error) {
	logger := s.logger.With(
		zap.String("method", "CreateExemption"),
		zap.String("student_id", req.StudentID.String()),
		zap.Time("from", req.FromDate),
		zap.Time("to", req.ToDate),
		zap.String("idempotency_key", idempotencyKey),
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
		var existing models.StudentAttendanceExemption
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.ExemptionID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "create", "attendance_exemption",
			&exemption.ExemptionID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"student_id": exemption.StudentID,
				"from_date":  exemption.FromDate,
				"to_date":    exemption.ToDate,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, string(EventAttendanceExemptionCreated), exemption.ExemptionID, TopicAttendance, exemption); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("exemption created", zap.String("exemption_id", exemption.ExemptionID.String()))
	return exemption, nil
}

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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "attendance_exemption",
			&req.ExemptionID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old_from_date": existing.FromDate,
				"new_from_date": req.FromDate,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, string(EventAttendanceExemptionUpdated), existing.ExemptionID, TopicAttendance, existing); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("exemption updated")
	return existing, nil
}

func (s *attendanceService) DeleteExemption(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteExemption"), zap.String("exemption_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete", "attendance_exemption",
			&id, "user", deletedBy, nil, nil, nil)
	}

	if err := s.storeOutboxEvent(ctx, tx, string(EventAttendanceExemptionDeleted), id, TopicAttendance, map[string]interface{}{
		"exemption_id": id,
		"deleted_by":   deletedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("exemption deleted")
	return nil
}

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

func (s *attendanceService) MarkPeriodAttendance(ctx context.Context, req MarkPeriodAttendanceRequest) (*models.StudentSessionAttendance, error) {
	logger := s.logger.With(
		zap.String("method", "MarkPeriodAttendance"),
		zap.String("session_id", req.SessionID.String()),
		zap.String("enrollment_id", req.EnrollmentID.String()),
	)

	if req.SessionID == uuid.Nil || req.EnrollmentID == uuid.Nil {
		return nil, fmt.Errorf("%w: session_id and enrollment_id are required", ErrInvalidInput)
	}
	if req.Status == "" {
		return nil, fmt.Errorf("%w: status is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	exists, err := s.attendanceSessionRepo.ExistsBySessionID(ctx, tx, req.SessionID)
	if err != nil {
		return nil, err
	}
	if !exists {
		attSession := &models.AttendanceSession{
			SessionID:  req.SessionID,
			MarkedBy:   req.MarkedBy,
			SourceType: &req.SourceType,
			Status:     models.AttendanceSessionCompleted,
		}
		if err := s.attendanceSessionRepo.Create(ctx, tx, attSession); err != nil {
			return nil, fmt.Errorf("failed to create attendance session lock: %w", err)
		}
	}

	existing, _ := s.studentSessionAttRepo.GetBySessionAndEnrollment(ctx, tx, req.SessionID, req.EnrollmentID)
	if existing != nil {
		isManualOverride := !existing.IsAuto && isAutoSource(req.SourceType)
		isAutoOverridden := existing.IsAuto && !isAutoSource(req.SourceType)
		if isManualOverride {
			logger.Info("biometric ignored because manual attendance already exists")
			return existing, nil
		}
		if isAutoOverridden {
			logger.Info("manual override of auto attendance",
				zap.String("old_status", string(existing.Status)),
				zap.String("new_status", string(req.Status)))
		}
	}

	now := time.Now()
	att := &models.StudentSessionAttendance{
		SessionID:    req.SessionID,
		EnrollmentID: req.EnrollmentID,
		Status:       req.Status,
		MarkedAt:     now,
		MarkedBy:     req.MarkedBy,
		SourceType:   req.SourceType,
		DeviceID:     req.DeviceID,
		IsAuto:       isAutoSource(req.SourceType),
		Remarks:      req.Remarks,
	}

	if err := s.studentSessionAttRepo.Upsert(ctx, tx, att); err != nil {
		return nil, err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "mark", "period_attendance",
			&att.AttendanceID, "user", req.MarkedBy, nil, nil, map[string]interface{}{
				"session_id":    req.SessionID,
				"enrollment_id": req.EnrollmentID,
				"status":        req.Status,
			})
	}

	// Use period attendance topic
	if err := s.storeOutboxEvent(ctx, tx, string(EventPeriodAttendanceMarked), att.AttendanceID, TopicPeriodAttendance, att); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("period attendance marked", zap.String("status", string(req.Status)))
	return att, nil
}

func (s *attendanceService) MarkPeriodAttendanceBiometric(ctx context.Context, req BiometricPunchRequest) (*models.StudentSessionAttendance, error) {
	logger := s.logger.With(
		zap.String("method", "MarkPeriodAttendanceBiometric"),
		zap.String("device_id", req.DeviceID),
		zap.String("user_code", req.DeviceUserCode),
	)

	mapping, err := s.biometricMappingRepo.GetByDeviceAndUserCode(ctx, s.pgClient.DB, req.DeviceID, req.DeviceUserCode)
	if err != nil {
		return nil, fmt.Errorf("biometric mapping not found: %w", err)
	}
	if mapping == nil {
		return nil, fmt.Errorf("no active mapping for device %s user %s", req.DeviceID, req.DeviceUserCode)
	}

	session, err := s.academicSessionRepo.GetActiveSessionForStudentAtTime(ctx, s.pgClient.DB,
		mapping.StudentID, req.CompanyID, req.PunchTime, req.PunchTime)
	if err != nil {
		return nil, fmt.Errorf("failed to find active session: %w", err)
	}
	if session == nil {
		return nil, fmt.Errorf("no active session found for student at %v", req.PunchTime)
	}

	enrollment, err := s.enrollmentRepo.GetActiveEnrollmentByStudentOnDate(ctx, s.pgClient.DB,
		req.CompanyID, mapping.StudentID, req.PunchTime)
	if err != nil || enrollment == nil {
		return nil, fmt.Errorf("no active enrollment found for student on date %v", req.PunchTime)
	}

	markReq := MarkPeriodAttendanceRequest{
		SessionID:    session.SessionID,
		EnrollmentID: enrollment.EnrollmentID,
		Status:       models.SessionPresent,
		SourceType:   models.SourceBiometric,
		DeviceID:     &req.DeviceID,
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	att, err := s.markPeriodAttendanceInternal(ctx, tx, markReq)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("biometric period attendance recorded", zap.String("session_id", session.SessionID.String()))
	return att, nil
}

func (s *attendanceService) markPeriodAttendanceInternal(ctx context.Context, tx *sql.Tx, req MarkPeriodAttendanceRequest) (*models.StudentSessionAttendance, error) {
	exists, err := s.attendanceSessionRepo.ExistsBySessionID(ctx, tx, req.SessionID)
	if err != nil {
		return nil, err
	}
	if !exists {
		attSession := &models.AttendanceSession{
			SessionID:  req.SessionID,
			MarkedBy:   req.MarkedBy,
			SourceType: &req.SourceType,
			Status:     models.AttendanceSessionCompleted,
		}
		if err := s.attendanceSessionRepo.Create(ctx, tx, attSession); err != nil {
			return nil, fmt.Errorf("failed to create attendance session lock: %w", err)
		}
	}

	existing, _ := s.studentSessionAttRepo.GetBySessionAndEnrollment(ctx, tx, req.SessionID, req.EnrollmentID)
	if existing != nil {
		if existing.IsAuto && !isAutoSource(req.SourceType) {
			// manual override allowed
		} else if !existing.IsAuto && isAutoSource(req.SourceType) {
			return existing, nil
		}
	}

	now := time.Now()
	att := &models.StudentSessionAttendance{
		SessionID:    req.SessionID,
		EnrollmentID: req.EnrollmentID,
		Status:       req.Status,
		MarkedAt:     now,
		MarkedBy:     req.MarkedBy,
		SourceType:   req.SourceType,
		DeviceID:     req.DeviceID,
		IsAuto:       isAutoSource(req.SourceType),
		Remarks:      req.Remarks,
	}

	if err := s.studentSessionAttRepo.Upsert(ctx, tx, att); err != nil {
		return nil, err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "mark", "period_attendance",
			&att.AttendanceID, "user", req.MarkedBy, nil, nil, map[string]interface{}{
				"session_id":    req.SessionID,
				"enrollment_id": req.EnrollmentID,
				"status":        req.Status,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, string(EventPeriodAttendanceMarked), att.AttendanceID, TopicPeriodAttendance, att); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}
	return att, nil
}

func (s *attendanceService) GetPeriodAttendanceBySession(ctx context.Context, sessionID uuid.UUID) ([]*models.StudentSessionAttendance, error) {
	filter := repository.StudentSessionAttendanceFilter{
		SessionID: &sessionID,
	}
	attendances, err := s.studentSessionAttRepo.List(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: 1000}, repository.Sort{Field: "marked_at", Direction: "ASC"})
	if err != nil {
		return nil, err
	}
	return attendances, nil
}

func (s *attendanceService) createAttendanceNotification(ctx context.Context, enrollmentID uuid.UUID, date time.Time, status models.AttendanceStatus, markedBy *uuid.UUID) {
	enrollment, err := s.enrollmentRepo.GetByIDUnsafe(ctx, s.pgClient.DB, enrollmentID)
	if err != nil || enrollment == nil {
		s.logger.Error("failed to fetch enrollment for notification", zap.Error(err))
		return
	}

	student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, enrollment.StudentID)
	if err != nil || student == nil {
		s.logger.Error("failed to fetch student for notification", zap.Error(err))
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
		return
	}

	notifReq := CreateNotificationRequest{
		CompanyID: student.CompanyID,
		Title:     title,
		Message:   message,
		Type:      models.NotificationTypeAlert,
		Priority:  models.PriorityNormal,
		Targets: []NotificationTargetInput{
			{
				TargetType:     models.TargetStudent,
				TargetEntityID: enrollment.StudentID,
			},
		},
		CreatedBy: markedBy,
	}

	if _, err := s.notificationSvc.Create(ctx, notifReq, ""); err != nil {
		s.logger.Error("failed to create attendance notification", zap.Error(err))
	}
}

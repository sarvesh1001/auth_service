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

// PeriodAttendanceService handles teacher web marking and override policy for period attendance.
type PeriodAttendanceService interface {
	// MarkSessionAttendance marks attendance for a single student in a session (teacher web/classroom).
	MarkSessionAttendance(ctx context.Context, req MarkPeriodAttendanceRequest, idempotencyKey string) (*models.StudentSessionAttendance, error)

	// BulkMarkSessionAttendance marks attendance for multiple students in the same session.
	BulkMarkSessionAttendance(ctx context.Context, sessionID uuid.UUID, marks []BulkPeriodAttendanceItem, markedBy *uuid.UUID, sourceType models.AttendanceSourceType) ([]*models.StudentSessionAttendance, error)

	// GetSessionAttendance retrieves all attendance records for a given session.
	GetSessionAttendance(ctx context.Context, sessionID uuid.UUID) ([]*models.StudentSessionAttendance, error)

	// GetStudentAttendanceForSession retrieves a specific student's attendance for a session.
	GetStudentAttendanceForSession(ctx context.Context, sessionID, enrollmentID uuid.UUID) (*models.StudentSessionAttendance, error)

	// GetTeacherSessions returns all sessions for a teacher on a given date (for UI).
	GetTeacherSessions(ctx context.Context, teacherID uuid.UUID, date time.Time) ([]*models.AcademicSession, error)

	// GetSectionSessions returns all sessions for a section on a given date.
	GetSectionSessions(ctx context.Context, sectionID uuid.UUID, date time.Time) ([]*models.AcademicSession, error)
}

type periodAttendanceService struct {
	academicSessionRepo   repository.AcademicSessionRepository
	studentSessionAttRepo repository.StudentSessionAttendanceRepository
	attendanceSessionRepo repository.AttendanceSessionRepository
	enrollmentRepo        repository.EnrollmentRepository
	sectionRepo           repository.SectionRepository
	teacherRepo           repository.TeacherRepository
	idempotencyStore      idempotency.Store
	auditService          *audit.AuditService
	outboxRepo            outbox.Repository
	pgClient              *client.PostgresClient
	logger                *zap.Logger
}

// NewPeriodAttendanceService creates a new instance.
func NewPeriodAttendanceService(
	academicSessionRepo repository.AcademicSessionRepository,
	studentSessionAttRepo repository.StudentSessionAttendanceRepository,
	attendanceSessionRepo repository.AttendanceSessionRepository,
	enrollmentRepo repository.EnrollmentRepository,
	sectionRepo repository.SectionRepository,
	teacherRepo repository.TeacherRepository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) PeriodAttendanceService {
	return &periodAttendanceService{
		academicSessionRepo:   academicSessionRepo,
		studentSessionAttRepo: studentSessionAttRepo,
		attendanceSessionRepo: attendanceSessionRepo,
		enrollmentRepo:        enrollmentRepo,
		sectionRepo:           sectionRepo,
		teacherRepo:           teacherRepo,
		idempotencyStore:      idempotencyStore,
		auditService:          auditService,
		outboxRepo:            outboxRepo,
		pgClient:              pgClient,
		logger:                logger.Named("period_attendance_service"),
	}
}

// MarkSessionAttendance implements teacher web marking with override policy.
func (s *periodAttendanceService) MarkSessionAttendance(ctx context.Context, req MarkPeriodAttendanceRequest, idempotencyKey string) (*models.StudentSessionAttendance, error) {
	logger := s.logger.With(
		zap.String("method", "MarkSessionAttendance"),
		zap.String("session_id", req.SessionID.String()),
		zap.String("enrollment_id", req.EnrollmentID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	// Validate input
	if req.SessionID == uuid.Nil || req.EnrollmentID == uuid.Nil {
		return nil, fmt.Errorf("%w: session_id and enrollment_id are required", ErrInvalidInput)
	}
	if req.Status == "" {
		return nil, fmt.Errorf("%w: status is required", ErrInvalidInput)
	}
	// Allowed statuses: present, absent, late, excused
	switch req.Status {
	case models.SessionPresent, models.SessionAbsent, models.SessionLate, models.SessionExcused:
		// valid
	default:
		return nil, fmt.Errorf("%w: invalid status %q", ErrInvalidInput, req.Status)
	}
	if req.SourceType == "" {
		req.SourceType = models.SourceWeb
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var existing models.StudentSessionAttendance
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.AttendanceID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			_ = tx.Commit()
			return &existing, nil
		}
	}

	// 1. Verify session exists and is not cancelled
	session, err := s.academicSessionRepo.GetByID(ctx, tx, req.SessionID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, fmt.Errorf("%w: session %s", ErrNotFound, req.SessionID)
	}
	if session.Status == models.SessionCancelled {
		return nil, fmt.Errorf("cannot mark attendance for cancelled session")
	}

	// 2. Verify enrollment is active for this session date
	enrollment, err := s.enrollmentRepo.GetByIDUnsafe(ctx, tx, req.EnrollmentID)
	if err != nil {
		return nil, err
	}
	if enrollment == nil {
		return nil, fmt.Errorf("%w: enrollment %s", ErrNotFound, req.EnrollmentID)
	}
	if enrollment.Status != "active" {
		return nil, fmt.Errorf("enrollment %s is not active", req.EnrollmentID)
	}
	if enrollment.SectionID != session.SectionID {
		return nil, fmt.Errorf("enrollment section %s does not match session section %s", enrollment.SectionID, session.SectionID)
	}
	// Check academic year covers session date
	academicYear, err := s.getAcademicYearByID(ctx, tx, enrollment.AcademicYearID)
	if err != nil {
		return nil, err
	}
	if academicYear == nil || session.SessionDate.Before(academicYear.StartDate) || session.SessionDate.After(academicYear.EndDate) {
		return nil, fmt.Errorf("session date %s is outside enrollment's academic year", session.SessionDate.Format("2006-01-02"))
	}

	// 3. Create or get attendance session lock (prevents concurrent marking)
	attSessionExists, err := s.attendanceSessionRepo.ExistsBySessionID(ctx, tx, req.SessionID)
	if err != nil {
		return nil, err
	}
	if !attSessionExists {
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

	// 4. Get existing attendance record (if any)
	existing, _ := s.studentSessionAttRepo.GetBySessionAndEnrollment(ctx, tx, req.SessionID, req.EnrollmentID)

	// 5. Override policy: manual (web/classroom/manual) always overrides auto (biometric)
	isManual := req.SourceType != models.SourceBiometric
	if existing != nil {
		if existing.IsAuto && isManual {
			logger.Info("manual override of auto attendance",
				zap.String("old_status", string(existing.Status)),
				zap.String("new_status", string(req.Status)))
		} else if !existing.IsAuto && !isManual {
			// biometric should not override manual teacher mark
			logger.Info("biometric ignored because manual attendance exists")
			_ = tx.Commit()
			return existing, nil
		}
	}

	// 6. Prepare attendance record
	now := time.Now().UTC()
	att := &models.StudentSessionAttendance{
		SessionID:    req.SessionID,
		EnrollmentID: req.EnrollmentID,
		Status:       req.Status,
		MarkedAt:     now,
		MarkedBy:     req.MarkedBy,
		SourceType:   req.SourceType,
		DeviceID:     req.DeviceID,
		IsAuto:       req.SourceType == models.SourceBiometric,
		Remarks:      req.Remarks,
	}

	// 7. Upsert
	if err := s.studentSessionAttRepo.Upsert(ctx, tx, att); err != nil {
		return nil, err
	}

	// 8. Idempotency store
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, att); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// 9. Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &enrollment.StudentID, "academics", "mark", "period_attendance",
			&att.AttendanceID, "teacher", req.MarkedBy, nil, nil, map[string]interface{}{
				"session_id":    req.SessionID,
				"enrollment_id": req.EnrollmentID,
				"status":        req.Status,
				"source_type":   req.SourceType,
			})
	}

	// 10. Outbox event
	payload, _ := json.Marshal(att)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "period_attendance",
		AggregateID:   att.AttendanceID.String(),
		EventType:     string(EventPeriodAttendanceMarked),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("period attendance marked", zap.String("status", string(req.Status)))
	return att, nil
}

// BulkMarkSessionAttendance marks attendance for multiple students in the same session.
func (s *periodAttendanceService) BulkMarkSessionAttendance(ctx context.Context, sessionID uuid.UUID, marks []BulkPeriodAttendanceItem, markedBy *uuid.UUID, sourceType models.AttendanceSourceType) ([]*models.StudentSessionAttendance, error) {
	logger := s.logger.With(
		zap.String("method", "BulkMarkSessionAttendance"),
		zap.String("session_id", sessionID.String()),
		zap.Int("count", len(marks)),
	)

	if sessionID == uuid.Nil {
		return nil, fmt.Errorf("%w: session_id is required", ErrInvalidInput)
	}
	if len(marks) == 0 {
		return nil, nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Verify session exists
	session, err := s.academicSessionRepo.GetByID(ctx, tx, sessionID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
	}
	if session.Status == models.SessionCancelled {
		return nil, fmt.Errorf("cannot mark attendance for cancelled session")
	}

	// Create attendance session lock if not exists
	attSessionExists, err := s.attendanceSessionRepo.ExistsBySessionID(ctx, tx, sessionID)
	if err != nil {
		return nil, err
	}
	if !attSessionExists {
		attSession := &models.AttendanceSession{
			SessionID:  sessionID,
			MarkedBy:   markedBy,
			SourceType: &sourceType,
			Status:     models.AttendanceSessionCompleted,
		}
		if err := s.attendanceSessionRepo.Create(ctx, tx, attSession); err != nil {
			return nil, fmt.Errorf("failed to create attendance session lock: %w", err)
		}
	}

	// Process each mark
	results := make([]*models.StudentSessionAttendance, 0, len(marks))
	for _, item := range marks {
		// Validate enrollment
		enrollment, err := s.enrollmentRepo.GetByIDUnsafe(ctx, tx, item.EnrollmentID)
		if err != nil || enrollment == nil {
			logger.Warn("skipping invalid enrollment", zap.String("enrollment_id", item.EnrollmentID.String()), zap.Error(err))
			continue
		}
		if enrollment.Status != "active" {
			logger.Warn("skipping inactive enrollment", zap.String("enrollment_id", item.EnrollmentID.String()))
			continue
		}
		if enrollment.SectionID != session.SectionID {
			logger.Warn("enrollment section mismatch", zap.String("enrollment_id", item.EnrollmentID.String()))
			continue
		}
		// Check academic year coverage
		academicYear, err := s.getAcademicYearByID(ctx, tx, enrollment.AcademicYearID)
		if err != nil || academicYear == nil || session.SessionDate.Before(academicYear.StartDate) || session.SessionDate.After(academicYear.EndDate) {
			logger.Warn("session date outside academic year", zap.String("enrollment_id", item.EnrollmentID.String()))
			continue
		}

		// Check existing for override policy
		existing, _ := s.studentSessionAttRepo.GetBySessionAndEnrollment(ctx, tx, sessionID, item.EnrollmentID)
		isManual := sourceType != models.SourceBiometric
		if existing != nil && !existing.IsAuto && !isManual {
			// biometric cannot override manual teacher mark
			logger.Info("skipping biometric for manually marked student", zap.String("enrollment_id", item.EnrollmentID.String()))
			continue
		}

		now := time.Now().UTC()
		att := &models.StudentSessionAttendance{
			SessionID:    sessionID,
			EnrollmentID: item.EnrollmentID,
			Status:       item.Status,
			MarkedAt:     now,
			MarkedBy:     markedBy,
			SourceType:   sourceType,
			IsAuto:       sourceType == models.SourceBiometric,
			Remarks:      item.Remarks,
		}
		if err := s.studentSessionAttRepo.Upsert(ctx, tx, att); err != nil {
			logger.Error("failed to upsert attendance", zap.String("enrollment_id", item.EnrollmentID.String()), zap.Error(err))
			continue
		}
		results = append(results, att)
	}

	// Audit log for bulk operation
	if s.auditService != nil && len(results) > 0 {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "bulk_mark", "period_attendance",
			nil, "teacher", markedBy, nil, nil, map[string]interface{}{
				"session_id":   sessionID,
				"marked_count": len(results),
				"source_type":  sourceType,
			})
	}

	// Outbox event for bulk
	if len(results) > 0 {
		payload, _ := json.Marshal(map[string]interface{}{
			"session_id":   sessionID,
			"marked_count": len(results),
			"source_type":  sourceType,
		})
		outboxEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "period_attendance",
			AggregateID:   sessionID.String(),
			EventType:     string(EventPeriodAttendanceMarked),
			Payload:       payload,
			Headers:       map[string]string{},
			Status:        "pending",
		}
		_ = s.outboxRepo.Store(ctx, tx, outboxEvent) // ignore error
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk period attendance marked", zap.Int("count", len(results)))
	return results, nil
}

// GetSessionAttendance retrieves all attendance records for a session.
func (s *periodAttendanceService) GetSessionAttendance(ctx context.Context, sessionID uuid.UUID) ([]*models.StudentSessionAttendance, error) {
	filter := repository.StudentSessionAttendanceFilter{
		SessionID: &sessionID,
	}
	attendances, err := s.studentSessionAttRepo.List(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: 1000}, repository.Sort{Field: "marked_at", Direction: "ASC"})
	if err != nil {
		return nil, err
	}
	return attendances, nil
}

// GetStudentAttendanceForSession retrieves a specific student's attendance for a session.
func (s *periodAttendanceService) GetStudentAttendanceForSession(ctx context.Context, sessionID, enrollmentID uuid.UUID) (*models.StudentSessionAttendance, error) {
	att, err := s.studentSessionAttRepo.GetBySessionAndEnrollment(ctx, s.pgClient.DB, sessionID, enrollmentID)
	if err != nil {
		return nil, err
	}
	if att == nil {
		return nil, fmt.Errorf("%w: attendance for session %s and enrollment %s", ErrNotFound, sessionID, enrollmentID)
	}
	return att, nil
}

// GetTeacherSessions returns all sessions for a teacher on a given date.
func (s *periodAttendanceService) GetTeacherSessions(ctx context.Context, teacherID uuid.UUID, date time.Time) ([]*models.AcademicSession, error) {
	filter := repository.AcademicSessionFilter{
		TeacherID:   &teacherID,
		SessionDate: &date,
	}
	sessions, err := s.academicSessionRepo.List(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: 100}, repository.Sort{Field: "start_time", Direction: "ASC"})
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// GetSectionSessions returns all sessions for a section on a given date.
func (s *periodAttendanceService) GetSectionSessions(ctx context.Context, sectionID uuid.UUID, date time.Time) ([]*models.AcademicSession, error) {
	filter := repository.AcademicSessionFilter{
		SectionID:   &sectionID,
		SessionDate: &date,
	}
	sessions, err := s.academicSessionRepo.List(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: 100}, repository.Sort{Field: "start_time", Direction: "ASC"})
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// Helper to fetch academic year by ID (needed because enrollmentRepo doesn't provide it directly)
func (s *periodAttendanceService) getAcademicYearByID(ctx context.Context, tx *sql.Tx, academicYearID uuid.UUID) (*models.AcademicYear, error) {
	query := `SELECT academic_year_id, start_date, end_date FROM academics.academic_year WHERE academic_year_id = $1 AND deleted_at IS NULL`
	var ay models.AcademicYear
	err := tx.QueryRowContext(ctx, query, academicYearID).Scan(&ay.AcademicYearID, &ay.StartDate, &ay.EndDate)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &ay, nil
}

// BulkPeriodAttendanceItem represents a single attendance mark for bulk operations.
type BulkPeriodAttendanceItem struct {
	EnrollmentID uuid.UUID                      `json:"enrollment_id"`
	Status       models.SessionAttendanceStatus `json:"status"`
	Remarks      string                         `json:"remarks,omitempty"`
}

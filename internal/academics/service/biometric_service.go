package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// BiometricService handles device punches for both period and full‑day attendance.
type BiometricService interface {
	// ProcessPunch processes a biometric punch for period attendance (college mode).
	ProcessPunch(ctx context.Context, req BiometricPunchRequest, idempotencyKey string) (*models.StudentSessionAttendance, error)

	// ProcessFullDayPunch processes a biometric punch for full‑day attendance (school mode).
	ProcessFullDayPunch(ctx context.Context, req BiometricPunchRequest, idempotencyKey string) (*models.StudentAttendance, error)
}

type biometricService struct {
	biometricMappingRepo repository.StudentBiometricMappingRepository
	academicSessionRepo  repository.AcademicSessionRepository
	enrollmentRepo       repository.EnrollmentRepository
	periodAttendanceSvc  PeriodAttendanceService
	fullDaySvc           AttendanceService
	idempotencyStore     idempotency.Store
	auditService         *audit.AuditService
	outboxRepo           outbox.Repository
	pgClient             *client.PostgresClient
	logger               *zap.Logger
}

// NewBiometricService creates a new instance with both period and full‑day dependencies.
func NewBiometricService(
	biometricMappingRepo repository.StudentBiometricMappingRepository,
	academicSessionRepo repository.AcademicSessionRepository,
	enrollmentRepo repository.EnrollmentRepository,
	periodAttendanceSvc PeriodAttendanceService,
	fullDaySvc AttendanceService,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) BiometricService {
	return &biometricService{
		biometricMappingRepo: biometricMappingRepo,
		academicSessionRepo:  academicSessionRepo,
		enrollmentRepo:       enrollmentRepo,
		periodAttendanceSvc:  periodAttendanceSvc,
		fullDaySvc:           fullDaySvc,
		idempotencyStore:     idempotencyStore,
		auditService:         auditService,
		outboxRepo:           outboxRepo,
		pgClient:             pgClient,
		logger:               logger.Named("biometric_service"),
	}
}

// ProcessPunch implements BiometricService for period attendance.
func (s *biometricService) ProcessPunch(ctx context.Context, req BiometricPunchRequest, idempotencyKey string) (*models.StudentSessionAttendance, error) {
	logger := s.logger.With(
		zap.String("method", "ProcessPunch"),
		zap.String("device_id", req.DeviceID),
		zap.String("user_code", req.DeviceUserCode),
		zap.Time("punch_time", req.PunchTime),
		zap.String("idempotency_key", idempotencyKey),
	)

	// Validate request
	if req.DeviceID == "" {
		return nil, fmt.Errorf("%w: device_id is required", ErrInvalidInput)
	}
	if req.DeviceUserCode == "" {
		return nil, fmt.Errorf("%w: device_user_code is required", ErrInvalidInput)
	}
	if req.PunchTime.IsZero() {
		req.PunchTime = time.Now().UTC()
	}
	if req.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}

	// Idempotency: composite key (device_id + user_code + rounded minute)
	if idempotencyKey == "" {
		idempotencyKey = fmt.Sprintf("punch:%s:%s:%d", req.DeviceID, req.DeviceUserCode, req.PunchTime.Unix()/60)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check idempotency store
	var existing models.StudentSessionAttendance
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.AttendanceID != uuid.Nil {
		logger.Info("idempotent request, returning cached attendance")
		_ = tx.Commit()
		return &existing, nil
	}

	// 1. Resolve student from biometric mapping
	mapping, err := s.biometricMappingRepo.GetByDeviceAndUserCode(ctx, tx, req.DeviceID, req.DeviceUserCode)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve mapping: %w", err)
	}
	if mapping == nil {
		return nil, fmt.Errorf("no active mapping for device %s user %s", req.DeviceID, req.DeviceUserCode)
	}
	if mapping.CompanyID != req.CompanyID {
		return nil, fmt.Errorf("mapping company mismatch: expected %s, got %s", req.CompanyID, mapping.CompanyID)
	}

	// 2. Find active academic session for this student at punch time
	session, err := s.academicSessionRepo.GetActiveSessionForStudentAtTime(ctx, tx,
		mapping.StudentID, req.CompanyID, req.PunchTime, req.PunchTime)
	if err != nil {
		return nil, fmt.Errorf("failed to find active session: %w", err)
	}
	if session == nil {
		return nil, fmt.Errorf("no active session found for student %s at %v", mapping.StudentID, req.PunchTime)
	}

	// 3. Find active enrollment for this student on the session date
	enrollment, err := s.enrollmentRepo.GetActiveEnrollmentByStudentOnDate(ctx, tx,
		req.CompanyID, mapping.StudentID, req.PunchTime)
	if err != nil {
		return nil, fmt.Errorf("failed to find active enrollment: %w", err)
	}
	if enrollment == nil {
		return nil, fmt.Errorf("no active enrollment for student %s on %v", mapping.StudentID, req.PunchTime)
	}

	// 4. Mark attendance using period attendance service (override policy applied)
	markReq := MarkPeriodAttendanceRequest{
		SessionID:    session.SessionID,
		EnrollmentID: enrollment.EnrollmentID,
		Status:       models.SessionPresent,
		MarkedBy:     nil,
		Remarks:      "auto-marked by biometric device",
		SourceType:   models.SourceBiometric,
		DeviceID:     &req.DeviceID,
	}

	// Commit mapping transaction before calling the period service (which starts its own)
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit mapping tx: %w", err)
	}

	att, err := s.periodAttendanceSvc.MarkSessionAttendance(ctx, markReq, idempotencyKey)
	if err != nil {
		logger.Error("failed to mark period attendance", zap.Error(err))
		return nil, fmt.Errorf("mark period attendance: %w", err)
	}

	// Audit and outbox – only if the attendance was actually created/updated by this biometric punch
	if att != nil && att.IsAuto && att.SourceType == models.SourceBiometric {
		// Audit log
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "academics", "process", "biometric_punch",
				&att.AttendanceID, "device", nil, nil, nil, map[string]interface{}{
					"device_id":  req.DeviceID,
					"user_code":  req.DeviceUserCode,
					"student_id": mapping.StudentID,
					"session_id": session.SessionID,
					"punch_time": req.PunchTime,
				})
		}

		// Outbox event with fresh transaction
		payload, _ := json.Marshal(map[string]interface{}{
			"device_id":        req.DeviceID,
			"device_user_code": req.DeviceUserCode,
			"student_id":       mapping.StudentID,
			"session_id":       session.SessionID,
			"attendance_id":    att.AttendanceID,
			"punch_time":       req.PunchTime,
		})
		outboxEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "biometric_punch",
			AggregateID:   att.AttendanceID.String(),
			EventType:     string(EventBiometricPunchProcessed), // cast to string
			Payload:       payload,
			Headers:       map[string]string{},
			Status:        "pending",
		}
		txOutbox, err := s.pgClient.BeginTx(ctx, nil)
		if err == nil {
			if err := s.outboxRepo.Store(ctx, txOutbox, outboxEvent); err != nil {
				logger.Error("failed to store outbox event", zap.Error(err))
			}
			_ = txOutbox.Commit()
		} else {
			logger.Error("failed to begin tx for outbox", zap.Error(err))
		}
	}

	logger.Info("biometric punch processed", zap.String("attendance_id", att.AttendanceID.String()))
	return att, nil
}

// ProcessFullDayPunch implements BiometricService for full‑day attendance.
func (s *biometricService) ProcessFullDayPunch(ctx context.Context, req BiometricPunchRequest, idempotencyKey string) (*models.StudentAttendance, error) {
	logger := s.logger.With(
		zap.String("method", "ProcessFullDayPunch"),
		zap.String("device_id", req.DeviceID),
		zap.String("user_code", req.DeviceUserCode),
		zap.Time("punch_time", req.PunchTime),
		zap.String("idempotency_key", idempotencyKey),
	)

	// Validate request
	if req.DeviceID == "" {
		return nil, fmt.Errorf("%w: device_id is required", ErrInvalidInput)
	}
	if req.DeviceUserCode == "" {
		return nil, fmt.Errorf("%w: device_user_code is required", ErrInvalidInput)
	}
	if req.PunchTime.IsZero() {
		req.PunchTime = time.Now().UTC()
	}
	if req.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}

	// Idempotency: use date‑based key (one full‑day per student per day)
	if idempotencyKey == "" {
		dateKey := req.PunchTime.UTC().Format("2006-01-02")
		idempotencyKey = fmt.Sprintf("full_punch:%s:%s:%s", req.DeviceID, req.DeviceUserCode, dateKey)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	var existing models.StudentAttendance
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.AttendanceID != uuid.Nil {
		logger.Info("idempotent request, returning cached attendance")
		_ = tx.Commit()
		return &existing, nil
	}

	// 1. Resolve student from biometric mapping
	mapping, err := s.biometricMappingRepo.GetByDeviceAndUserCode(ctx, tx, req.DeviceID, req.DeviceUserCode)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve mapping: %w", err)
	}
	if mapping == nil {
		return nil, fmt.Errorf("no active mapping for device %s user %s", req.DeviceID, req.DeviceUserCode)
	}
	if mapping.CompanyID != req.CompanyID {
		return nil, fmt.Errorf("mapping company mismatch: expected %s, got %s", req.CompanyID, mapping.CompanyID)
	}

	// 2. Find active enrollment for this student on punch date
	punchDate := req.PunchTime.UTC().Truncate(24 * time.Hour)
	enrollment, err := s.enrollmentRepo.GetActiveEnrollmentByStudentOnDate(ctx, tx,
		req.CompanyID, mapping.StudentID, punchDate)
	if err != nil {
		return nil, fmt.Errorf("failed to find active enrollment: %w", err)
	}
	if enrollment == nil {
		return nil, fmt.Errorf("no active enrollment for student %s on %s", mapping.StudentID, punchDate.Format("2006-01-02"))
	}

	// Commit mapping transaction before calling full‑day service (which starts its own)
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit mapping tx: %w", err)
	}

	// 3. Prepare full‑day attendance request
	// StatusPresent is models.StatusPresent, and SourceType is a pointer
	sourceType := models.SourceBiometric
	markReq := MarkAttendanceRequest{
		EnrollmentID: enrollment.EnrollmentID,
		Date:         punchDate,
		Status:       models.StatusPresent,
		MarkedBy:     nil,
		Remarks:      "auto-marked by biometric device",
		SourceType:   &sourceType,
		DeviceID:     &req.DeviceID,
	}

	// 4. Call full‑day attendance service (handles override policy)
	att, err := s.fullDaySvc.MarkAttendance(ctx, markReq, idempotencyKey)
	if err != nil {
		logger.Error("failed to mark full-day attendance", zap.Error(err))
		return nil, fmt.Errorf("mark full-day attendance: %w", err)
	}

	// Audit and outbox – only if the attendance was actually created/updated by this biometric punch
	// att.SourceType is *models.AttendanceSourceType, so compare the dereferenced value
	if att != nil && att.SourceType != nil && *att.SourceType == models.SourceBiometric {
		// Audit log
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "academics", "process", "biometric_full_punch",
				&att.AttendanceID, "device", nil, nil, nil, map[string]interface{}{
					"device_id":  req.DeviceID,
					"user_code":  req.DeviceUserCode,
					"student_id": mapping.StudentID,
					"date":       punchDate,
				})
		}

		// Outbox event with fresh transaction
		payload, _ := json.Marshal(map[string]interface{}{
			"device_id":        req.DeviceID,
			"device_user_code": req.DeviceUserCode,
			"student_id":       mapping.StudentID,
			"attendance_id":    att.AttendanceID,
			"date":             punchDate,
		})
		outboxEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "biometric_full_punch",
			AggregateID:   att.AttendanceID.String(),
			EventType:     string(EventBiometricFullPunchProcessed),
			Payload:       payload,
			Headers:       map[string]string{},
			Status:        "pending",
		}
		txOutbox, err := s.pgClient.BeginTx(ctx, nil)
		if err == nil {
			if err := s.outboxRepo.Store(ctx, txOutbox, outboxEvent); err != nil {
				logger.Error("failed to store outbox event", zap.Error(err))
			}
			_ = txOutbox.Commit()
		} else {
			logger.Error("failed to begin tx for outbox", zap.Error(err))
		}
	}

	logger.Info("biometric full-day punch processed", zap.String("attendance_id", att.AttendanceID.String()))
	return att, nil
}

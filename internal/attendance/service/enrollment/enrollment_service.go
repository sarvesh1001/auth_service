package enrollment

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	auditservice "auth-service/internal/infrastructure/audit"
)

type EnrollmentService interface {
	EnrollSubject(ctx context.Context, companyID uuid.UUID, subjectType string, subjectID uuid.UUID, deviceID, sourceType, deviceUserCode string, enrolledBy *uuid.UUID) error
	RevokeEnrollment(ctx context.Context, companyID uuid.UUID, deviceID, sourceType, deviceUserCode string, reason string, revokedBy *uuid.UUID) error
	UnrevokeEnrollment(ctx context.Context, companyID uuid.UUID, deviceID, sourceType, deviceUserCode string, reason string, actedBy *uuid.UUID) (*models.DeviceEnrollment, error)
	ResolveEnrollment(ctx context.Context, companyID uuid.UUID, deviceID, sourceType, deviceUserCode string) (*models.DeviceEnrollment, error)
	GetEnrollmentsByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) ([]*models.DeviceEnrollment, error)
	GetEnrollmentsBySubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string) ([]*models.DeviceEnrollment, error)
	GetRevokedEnrollmentsByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) ([]*models.DeviceEnrollment, error)
}

type enrollmentService struct {
	enrollmentRepo repository.DeviceEnrollmentRepository
	deviceRepo     repository.DeviceRepository
	sourceRepo     repository.SourceRepository
	audit          *auditservice.AuditService
	logger         *zap.Logger
}

func NewEnrollmentService(
	enrollmentRepo repository.DeviceEnrollmentRepository,
	deviceRepo repository.DeviceRepository,
	sourceRepo repository.SourceRepository,
	audit *auditservice.AuditService,
	logger *zap.Logger,
) EnrollmentService {
	return &enrollmentService{
		enrollmentRepo: enrollmentRepo,
		deviceRepo:     deviceRepo,
		sourceRepo:     sourceRepo,
		audit:          audit,
		logger:         logger,
	}
}

func (s *enrollmentService) ensureSourceExists(ctx context.Context, companyID uuid.UUID, sourceType string, actor *uuid.UUID) error {
	src, err := s.sourceRepo.GetByType(ctx, companyID, sourceType)
	if err != nil {
		return err
	}
	if src != nil {
		if !src.IsActive {
			return errors.New("attendance source disabled by admin")
		}
		return nil
	}
	newSource := &models.AttendanceSource{
		SourceID:   uuid.New(),
		CompanyID:  companyID,
		SourceType: sourceType,
		Name:       strings.Title(sourceType) + " Attendance",
		IsActive:   true,
		CreatedAt:  time.Now().UTC(),
		CreatedBy:  actor,
	}
	return s.sourceRepo.Create(ctx, nil, newSource) // tx nil for simplicity
}

func (s *enrollmentService) EnrollSubject(ctx context.Context, companyID uuid.UUID, subjectType string, subjectID uuid.UUID, deviceID, sourceType, deviceUserCode string, enrolledBy *uuid.UUID) error {
	if err := s.ensureSourceExists(ctx, companyID, sourceType, enrolledBy); err != nil {
		return err
	}
	device, err := s.deviceRepo.GetActiveDevice(ctx, companyID, deviceID)
	if err != nil || device == nil || !device.IsTrusted {
		return errors.New("invalid or untrusted device")
	}
	exists, err := s.enrollmentRepo.ExistsActive(ctx, companyID, deviceID, sourceType, deviceUserCode)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("device user code already enrolled")
	}
	enrollment := &models.DeviceEnrollment{
		MappingID:         uuid.New(),
		CompanyID:         companyID,
		SubjectType:       subjectType,
		SubjectID:         subjectID,
		DeviceID:          deviceID,
		SourceType:        sourceType,
		DeviceUserCode:    deviceUserCode,
		IsActive:          true,
		EnrollmentVersion: 1,
		EnrolledAt:        time.Now().UTC(),
		CreatedBy:         enrolledBy,
	}
	return s.enrollmentRepo.Create(ctx, enrollment)
}

func (s *enrollmentService) RevokeEnrollment(ctx context.Context, companyID uuid.UUID, deviceID, sourceType, deviceUserCode string, reason string, revokedBy *uuid.UUID) error {
	enrollment, err := s.enrollmentRepo.GetActive(ctx, companyID, deviceID, sourceType, deviceUserCode)
	if err != nil || enrollment == nil {
		return errors.New("active enrollment not found")
	}
	return s.enrollmentRepo.Revoke(ctx, enrollment.MappingID, reason, revokedBy)
}

func (s *enrollmentService) UnrevokeEnrollment(ctx context.Context, companyID uuid.UUID, deviceID, sourceType, deviceUserCode string, reason string, actedBy *uuid.UUID) (*models.DeviceEnrollment, error) {
	if err := s.ensureSourceExists(ctx, companyID, sourceType, actedBy); err != nil {
		return nil, err
	}
	// Find the revoked enrollment
	revoked, err := s.enrollmentRepo.GetRevoked(ctx, companyID, deviceID, sourceType, deviceUserCode)
	if err != nil {
		return nil, err
	}
	if revoked == nil {
		return nil, errors.New("no revoked enrollment found for the given device and user code")
	}
	// Unrevoke it
	if err := s.enrollmentRepo.Unrevoke(ctx, revoked.MappingID, reason, actedBy); err != nil {
		return nil, err
	}
	// Return the now‑active enrollment
	return s.enrollmentRepo.GetActive(ctx, companyID, deviceID, sourceType, deviceUserCode)
}

func (s *enrollmentService) ResolveEnrollment(ctx context.Context, companyID uuid.UUID, deviceID, sourceType, deviceUserCode string) (*models.DeviceEnrollment, error) {
	device, err := s.deviceRepo.GetActiveDevice(ctx, companyID, deviceID)
	if err != nil || device == nil || !device.IsTrusted {
		return nil, errors.New("invalid or untrusted device")
	}
	enrollment, err := s.enrollmentRepo.GetActive(ctx, companyID, deviceID, sourceType, deviceUserCode)
	if err != nil {
		return nil, err
	}
	if enrollment == nil {
		return nil, errors.New("no active enrollment found")
	}
	_ = s.enrollmentRepo.UpdateLastUsed(ctx, enrollment.MappingID)
	return enrollment, nil
}

func (s *enrollmentService) GetEnrollmentsByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) ([]*models.DeviceEnrollment, error) {
	return s.enrollmentRepo.GetByDevice(ctx, companyID, deviceID)
}

func (s *enrollmentService) GetEnrollmentsBySubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string) ([]*models.DeviceEnrollment, error) {
	return s.enrollmentRepo.GetActiveBySubject(ctx, companyID, subjectID, subjectType)
}

func (s *enrollmentService) GetRevokedEnrollmentsByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) ([]*models.DeviceEnrollment, error) {
	return s.enrollmentRepo.GetRevokedByDevice(ctx, companyID, deviceID)
}

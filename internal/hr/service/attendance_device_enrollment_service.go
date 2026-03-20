package service

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	a "auth-service/internal/infrastructure/audit"
	"auth-service/internal/util"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// =====================================================
// SERVICE INTERFACE
// =====================================================

type AttendanceDeviceEnrollmentService interface {
	EnrollUser(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		deviceID string,
		sourceType string,
		deviceUserCode string,
		enrolledBy *uuid.UUID,
	) error
	ResolveEnrollment(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		sourceType string,
		deviceUserCode string,
	) (*attendance.UserDeviceIdentifier, error)

	UnrevokeEnrollment(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		sourceType string,
		deviceUserCode string,
		reason string,
		actedBy *uuid.UUID,
	) (*attendance.UserDeviceIdentifier, error)

	RevokeEnrollment(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		sourceType string,
		deviceUserCode string,
		reason string,
		revokedBy *uuid.UUID,
	) error

	ResolveUser(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		sourceType string,
		deviceUserCode string,
	) (uuid.UUID, error)

	GetEnrollmentsByDevice(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
	) ([]*attendance.UserDeviceIdentifier, error)

	GetEnrollmentsByUser(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
	) ([]*attendance.UserDeviceIdentifier, error)

	GetRevokedEnrollmentsByDevice(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
	) ([]*attendance.UserDeviceIdentifier, error)

	ValidateEnrollment(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		sourceType string,
		deviceUserCode string,
	) (*attendance.UserDeviceIdentifier, error)
}

// =====================================================
// SERVICE IMPLEMENTATION
// =====================================================

type attendanceDeviceEnrollmentService struct {
	enrollmentRepo repository.DeviceEnrollmentRepository
	deviceRepo     repository.AttendanceDeviceRepository
	attendanceRepo repository.AttendanceRepository
	auditService   *a.AuditService
	logger         *zap.Logger
}

func NewAttendanceDeviceEnrollmentService(
	enrollmentRepo repository.DeviceEnrollmentRepository,
	deviceRepo repository.AttendanceDeviceRepository,
	attendanceRepo repository.AttendanceRepository,
	auditService *a.AuditService,
	logger *zap.Logger,
) AttendanceDeviceEnrollmentService {
	return &attendanceDeviceEnrollmentService{
		enrollmentRepo: enrollmentRepo,
		deviceRepo:     deviceRepo,
		attendanceRepo: attendanceRepo,
		auditService:   auditService,
		logger:         logger,
	}
}

// =====================================================
// 🔥 ENSURE ATTENDANCE SOURCE EXISTS (HYBRID CORE)
// =====================================================

func (s *attendanceDeviceEnrollmentService) ensureAttendanceSourceExists(
	ctx context.Context,
	companyID uuid.UUID,
	sourceType string,
	actor *uuid.UUID,
) error {

	source, err := s.attendanceRepo.GetAttendanceSourceByCompanyAndType(
		ctx,
		companyID,
		sourceType,
	)
	if err != nil {
		return err
	}

	// Exists + active → OK
	if source != nil {
		if !source.IsActive {
			return errors.New("attendance source disabled by admin")
		}
		return nil
	}

	// Auto-create (DX)
	newSource := &attendance.AttendanceSource{
		SourceID:   uuid.New(),
		CompanyID:  companyID,
		SourceType: sourceType,
		Name:       strings.Title(sourceType) + " Attendance",
		IsActive:   true,
		CreatedAt:  time.Now().UTC(),
		CreatedBy:  actor,
	}

	s.logger.Info(
		"Auto-creating attendance source",
		util.String("company_id", companyID.String()),
		util.String("source_type", sourceType),
	)

	return s.attendanceRepo.CreateAttendanceSource(ctx, newSource)
}

// =====================================================
// ENROLL USER
// =====================================================

func (s *attendanceDeviceEnrollmentService) EnrollUser(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	deviceID string,
	sourceType string,
	deviceUserCode string,
	enrolledBy *uuid.UUID,
) error {

	// 🔥 Ensure source exists
	if err := s.ensureAttendanceSourceExists(
		ctx,
		companyID,
		sourceType,
		enrolledBy,
	); err != nil {
		return err
	}

	device, err := s.deviceRepo.GetActiveDevice(ctx, companyID, deviceID)
	if err != nil {
		return fmt.Errorf("failed to get device: %w", err)
	}
	if device == nil {
		return errors.New("device not found or inactive")
	}
	if !device.IsTrusted {
		return errors.New("device is not trusted")
	}

	exists, err := s.enrollmentRepo.ExistsActiveEnrollment(
		ctx,
		companyID,
		deviceID,
		sourceType,
		deviceUserCode,
	)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("device user code already enrolled")
	}

	enrollment := &attendance.UserDeviceIdentifier{
		CompanyID:         companyID,
		UserID:            userID,
		DeviceID:          deviceID,
		SourceType:        sourceType,
		DeviceUserCode:    deviceUserCode,
		IsActive:          true,
		EnrollmentVersion: 1,
		EnrolledAt:        time.Now().UTC(),
		CreatedBy:         enrolledBy,
	}

	if err := s.enrollmentRepo.Create(ctx, enrollment); err != nil {
		return err
	}

	return nil
}

// =====================================================
// REVOKE ENROLLMENT
// =====================================================

func (s *attendanceDeviceEnrollmentService) RevokeEnrollment(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	sourceType string,
	deviceUserCode string,
	reason string,
	revokedBy *uuid.UUID,
) error {

	enrollment, err := s.enrollmentRepo.GetActive(
		ctx,
		companyID,
		deviceID,
		sourceType,
		deviceUserCode,
	)
	if err != nil {
		return err
	}
	if enrollment == nil {
		return errors.New("active enrollment not found")
	}

	return s.enrollmentRepo.Revoke(
		ctx,
		enrollment.MappingID,
		reason,
		revokedBy,
	)
}

// =====================================================
// UNREVOKE ENROLLMENT
// =====================================================

func (s *attendanceDeviceEnrollmentService) UnrevokeEnrollment(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	sourceType string,
	deviceUserCode string,
	reason string,
	actedBy *uuid.UUID,
) (*attendance.UserDeviceIdentifier, error) {

	// 🔥 Ensure source exists
	if err := s.ensureAttendanceSourceExists(
		ctx,
		companyID,
		sourceType,
		actedBy,
	); err != nil {
		return nil, err
	}

	return s.enrollmentRepo.UnrevokeEnrollment(
		ctx,
		companyID,
		deviceID,
		deviceUserCode,
		sourceType,
		actedBy,
		reason,
	)
}

// =====================================================
// RESOLVE USER (INGEST)
// =====================================================

func (s *attendanceDeviceEnrollmentService) ResolveUser(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	sourceType string,
	deviceUserCode string,
) (uuid.UUID, error) {

	enrollment, err := s.ValidateEnrollment(
		ctx,
		companyID,
		deviceID,
		sourceType,
		deviceUserCode,
	)
	if err != nil {
		return uuid.Nil, err
	}

	_ = s.enrollmentRepo.UpdateLastUsed(ctx, enrollment.MappingID)
	return enrollment.UserID, nil
}

// =====================================================
// VALIDATE ENROLLMENT
// =====================================================

func (s *attendanceDeviceEnrollmentService) ValidateEnrollment(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	sourceType string,
	deviceUserCode string,
) (*attendance.UserDeviceIdentifier, error) {

	device, err := s.deviceRepo.GetActiveDevice(ctx, companyID, deviceID)
	if err != nil {
		return nil, err
	}
	if device == nil || !device.IsTrusted {
		return nil, errors.New("invalid or untrusted device")
	}

	enrollment, err := s.enrollmentRepo.GetActive(
		ctx,
		companyID,
		deviceID,
		sourceType,
		deviceUserCode,
	)
	if err != nil {
		return nil, err
	}
	if enrollment == nil {
		return nil, errors.New("no active enrollment found")
	}

	return enrollment, nil
}

// =====================================================
// QUERIES
// =====================================================

func (s *attendanceDeviceEnrollmentService) GetEnrollmentsByDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) ([]*attendance.UserDeviceIdentifier, error) {
	return s.enrollmentRepo.GetEnrollmentsByDevice(ctx, companyID, deviceID)
}

func (s *attendanceDeviceEnrollmentService) GetEnrollmentsByUser(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
) ([]*attendance.UserDeviceIdentifier, error) {
	return s.enrollmentRepo.GetEnrollmentsByUser(ctx, companyID, userID)
}

func (s *attendanceDeviceEnrollmentService) GetRevokedEnrollmentsByDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) ([]*attendance.UserDeviceIdentifier, error) {

	device, err := s.deviceRepo.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, errors.New("device not found")
	}

	return s.enrollmentRepo.GetRevokedEnrollmentsByDevice(ctx, companyID, deviceID)
}

// =====================================================
// RESOLVE ENROLLMENT (INGEST - DEVICE SAFE)
// =====================================================

func (s *attendanceDeviceEnrollmentService) ResolveEnrollment(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	sourceType string,
	deviceUserCode string,
) (*attendance.UserDeviceIdentifier, error) {

	enrollment, err := s.ValidateEnrollment(
		ctx,
		companyID,
		deviceID,
		sourceType,
		deviceUserCode,
	)
	if err != nil {
		return nil, err
	}

	// Update last-used timestamp (non-blocking)
	_ = s.enrollmentRepo.UpdateLastUsed(ctx, enrollment.MappingID)

	return enrollment, nil
}

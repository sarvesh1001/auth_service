package repository

import (
	"context"

	"auth-service/internal/attendance/models"

	"github.com/google/uuid"
)

type DeviceEnrollmentRepository interface {
	Create(ctx context.Context, enrollment *models.DeviceEnrollment) error

	GetActive(ctx context.Context, companyID uuid.UUID, deviceID, sourceType, deviceUserCode string) (*models.DeviceEnrollment, error)

	GetRevoked(ctx context.Context, companyID uuid.UUID, deviceID, sourceType, deviceUserCode string) (*models.DeviceEnrollment, error)

	GetActiveBySubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string) ([]*models.DeviceEnrollment, error)

	GetByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) ([]*models.DeviceEnrollment, error)

	GetRevokedByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) ([]*models.DeviceEnrollment, error)

	Revoke(ctx context.Context, mappingID uuid.UUID, reason string, revokedBy *uuid.UUID) error

	Unrevoke(ctx context.Context, mappingID uuid.UUID, reason string, actedBy *uuid.UUID) error

	UpdateLastUsed(ctx context.Context, mappingID uuid.UUID) error

	ExistsActive(ctx context.Context, companyID uuid.UUID, deviceID, sourceType, deviceUserCode string) (bool, error)

	IncrementVersion(ctx context.Context, mappingID uuid.UUID) error
}

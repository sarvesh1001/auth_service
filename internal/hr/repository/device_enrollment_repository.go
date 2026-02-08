package repository

import (
	"auth-service/internal/hr/models/attendance"
	"context"

	"github.com/google/uuid"
)

type DeviceEnrollmentRepository interface {

	// ==========================
	// CREATE
	// ==========================
	Create(
		ctx context.Context,
		enrollment *attendance.UserDeviceIdentifier,
	) error

	// ==========================
	// READ (STRICT ACTIVE)
	// ==========================
	GetActive(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		sourceType string,
		deviceUserCode string,
	) (*attendance.UserDeviceIdentifier, error)

	// ==========================
	// REVOKE (SAFE, BY MAPPING)
	// ==========================
	Revoke(
		ctx context.Context,
		mappingID uuid.UUID,
		reason string,
		revokedBy *uuid.UUID,
	) error

	// ==========================
	// VALIDATION
	// ==========================
	ExistsActiveEnrollment(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		sourceType string,
		deviceUserCode string,
	) (bool, error)

	// ==========================
	// QUERIES
	// ==========================
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

	// ==========================
	// UPDATES
	// ==========================
	IncrementVersion(
		ctx context.Context,
		mappingID uuid.UUID,
	) error

	UpdateLastUsed(
		ctx context.Context,
		mappingID uuid.UUID,
	) error
	UnrevokeEnrollment(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		deviceUserCode string,
		sourceType string,
		actedBy *uuid.UUID,
		reason string,
	) (*attendance.UserDeviceIdentifier, error)

	// GetRevokedEnrollmentsByDevice lists revoked enrollments for a device
	GetRevokedEnrollmentsByDevice(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
	) ([]*attendance.UserDeviceIdentifier, error)
}

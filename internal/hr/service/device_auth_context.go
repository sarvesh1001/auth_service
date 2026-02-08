package service

import "github.com/google/uuid"

// DeviceAuthContext represents the authentication context for a device
type DeviceAuthContext struct {
	DeviceID       string
	CompanyID      uuid.UUID
	SourceType     string
	IsTrusted      bool
	DeviceCode     string
	WorkCenterCode *string
	LocationID     *uuid.UUID
}

// NewDeviceAuthContext creates a new device auth context
func NewDeviceAuthContext(deviceID string, companyID uuid.UUID, sourceType string, isTrusted bool) *DeviceAuthContext {
	return &DeviceAuthContext{
		DeviceID:   deviceID,
		CompanyID:  companyID,
		SourceType: sourceType,
		IsTrusted:  isTrusted,
	}
}

// IsValid checks if the device auth context is valid
func (d *DeviceAuthContext) IsValid() bool {
	return d.DeviceID != "" && d.CompanyID != uuid.Nil && d.SourceType != "" && d.IsTrusted
}

// DeviceSessionKey returns a unique key for device session
func (d *DeviceAuthContext) DeviceSessionKey() string {
	return d.CompanyID.String() + ":" + d.DeviceID + ":" + d.SourceType
}

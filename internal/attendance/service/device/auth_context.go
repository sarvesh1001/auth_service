package device

import "github.com/google/uuid"

type DeviceAuthContext struct {
	DeviceID       string
	CompanyID      uuid.UUID
	SourceType     string
	IsTrusted      bool
	DeviceCode     string
	WorkCenterCode *string
	LocationID     *uuid.UUID
}

func NewDeviceAuthContext(deviceID string, companyID uuid.UUID, sourceType string, isTrusted bool) *DeviceAuthContext {
	return &DeviceAuthContext{
		DeviceID:   deviceID,
		CompanyID:  companyID,
		SourceType: sourceType,
		IsTrusted:  isTrusted,
	}
}

func (d *DeviceAuthContext) IsValid() bool {
	return d.DeviceID != "" && d.CompanyID != uuid.Nil && d.SourceType != "" && d.IsTrusted
}

func (d *DeviceAuthContext) DeviceSessionKey() string {
	return d.CompanyID.String() + ":" + d.DeviceID + ":" + d.SourceType
}

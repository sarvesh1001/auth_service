// internal/models/device_trust.go

package models

import (
    "time"
    "github.com/google/uuid"
)

type DeviceTrustStatus string

const (
    TrustStatusPrimary   DeviceTrustStatus = "primary"
    TrustStatusTrusted   DeviceTrustStatus = "trusted"
    TrustStatusUntrusted DeviceTrustStatus = "untrusted"
)

type DeviceTrustLevel struct {
    UserID               uuid.UUID
    DeviceID             string
    TrustStatus          DeviceTrustStatus
    FirstSuccessfulLogin *time.Time
    LastLogin            *time.Time
    IPAddress            string
    UserAgent            string
    IsBlocked            bool
}

type UserDataDeletion struct {
    DeletionID        uuid.UUID
    UserID            uuid.UUID
    DeviceID          string
    Reason            string
    DeletedAt         time.Time
    DataWipedCategories []string
    DeletedBy         *uuid.UUID // admin_id if admin action
}
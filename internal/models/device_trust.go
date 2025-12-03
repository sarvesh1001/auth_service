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
	UserID      uuid.UUID
	DeviceID    string
	TrustStatus DeviceTrustStatus

	// Device Identity
	DeviceFingerprint string // hash(DeviceID + model + version + UA)
	OSVersion         string // e.g., iOS 17, Android 14
	AppVersion        string // app build version during trust registration

	// Network Identity
	LastIPAddress    string
	LastIPSubnet     string // `/24` subnet for consistency
	LastLocationHash string // city-level or region-level hash (no PII)

	// Browser/UA Identity
	UserAgent   string
	DeviceModel string // e.g., iPhone 13, Samsung A52

	// Login History
	FirstSuccessfulLogin *time.Time
	LastLogin            *time.Time

	// Security Flags
	IsBlocked bool
	RiskScore int
}

type UserDataDeletion struct {
	DeletionID          uuid.UUID
	UserID              uuid.UUID
	DeviceID            string
	Reason              string
	DeletedAt           time.Time
	DataWipedCategories []string
	DeletedBy           *uuid.UUID // admin_id if admin action
}

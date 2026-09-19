package models

import (
	"time"

	"github.com/google/uuid"
)

// TrustBindingResult is the atomic outcome of BindAndTrust.
// If Trusted == false, the caller MUST reject the admin login.
// State reuses the existing DeviceTrustStatus enum (primary / trusted / untrusted).
type TrustBindingResult struct {
	Trusted     bool
	State       DeviceTrustStatus
	Reason      string
	AdminID     uuid.UUID
	DeviceID    string
	BindToken   string
	IPAddress   string
	IPSubnet    string
	Fingerprint string // canonical hash, may be ""
	UpdatedAt   time.Time
}

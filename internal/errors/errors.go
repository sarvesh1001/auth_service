package errors

import "errors"

var (
	// ---- General errors ----
	ErrNotFound         = errors.New("not found")
	ErrInvalidInput     = errors.New("invalid input")
	ErrDuplicate        = errors.New("duplicate record")
	ErrConflict         = errors.New("conflict")
	ErrPermissionDenied = errors.New("permission denied")
	ErrUnauthorized     = errors.New("unauthorized")
	ErrInternal         = errors.New("internal server error")

	// ---- Admin/user errors ----
	ErrInvalidState       = errors.New("invalid state")
	ErrInvalidStatus      = errors.New("invalid status")
	ErrInvalidTransition  = errors.New("invalid state transition")
	ErrAdminInactive      = errors.New("admin is inactive")
	ErrRoleInUse          = errors.New("role is in use and cannot be deleted")
	ErrSystemRole         = errors.New("system role cannot be modified")
	ErrSuperAdminRequired = errors.New("super admin privileges required")

	// ---- Admin device errors ----
	ErrDeviceNotFound           = errors.New("device not found")
	ErrDeviceAlreadyBound       = errors.New("device already bound to another admin")
	ErrDeviceNotTrusted         = errors.New("device is not trusted")
	ErrDeviceBlocked            = errors.New("device is blocked")
	ErrInvalidDeviceID          = errors.New("invalid device identifier")
	ErrBindingTokenMismatch     = errors.New("binding token does not match")
	ErrDeviceBindingExpired     = errors.New("device binding has expired")
	ErrDeviceAlreadyActive      = errors.New("device is already active for this admin")
	ErrDeviceNotActive          = errors.New("device is not active")
	ErrTooManyDevices           = errors.New("admin has too many active devices")
	ErrDeviceVerificationFailed = errors.New("device verification failed")

	// ---- Admin MPIN errors ----
	ErrAdminMPINNotFound          = errors.New("admin MPIN not found")
	ErrAdminMPINInvalid           = errors.New("invalid admin MPIN")
	ErrAdminMPINLocked            = errors.New("admin MPIN is locked")
	ErrAdminMPINAlreadyExists     = errors.New("admin MPIN already exists")
	ErrAdminMPINTooWeak           = errors.New("admin MPIN is too weak")
	ErrAdminMPINRateLimitExceeded = errors.New("MPIN rate limit exceeded")
	ErrAdminMPINAttemptsExceeded  = errors.New("maximum MPIN attempts exceeded")

	// ---- OTP errors ----
	ErrOTPRateLimitExceeded = errors.New("OTP rate limit exceeded")
	ErrOTPNotFound          = errors.New("OTP not found")
	ErrOTPInvalid           = errors.New("invalid OTP")
	ErrOTPExpired           = errors.New("OTP expired")
	ErrOTPAttemptsExceeded  = errors.New("maximum OTP attempts exceeded")
	ErrOTPReplayAttempt     = errors.New("OTP replay attempt detected")
	ErrPhoneNotRegistered   = errors.New("phone number not registered")
	ErrSecurityCheckFailed  = errors.New("security check failed")
	ErrDailyQuotaExceeded   = errors.New("daily OTP quota exceeded")
	ErrOTPAlreadyVerified   = errors.New("OTP already verified")
	ErrOTPBlocked           = errors.New("OTP blocked for this phone")
)

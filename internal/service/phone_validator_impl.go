package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	appErrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
)

// PhoneValidatorImpl provides phone number validation and ID lookup for both users and admins.
type PhoneValidatorImpl struct {
	userService  *UserService
	adminService *AdminService
	auditService *audit.AuditService
}

// NewPhoneValidator creates a new PhoneValidatorImpl.
// Either userService or adminService can be nil if not needed.
func NewPhoneValidator(
	userService *UserService,
	adminService *AdminService,
	auditService *audit.AuditService,
) *PhoneValidatorImpl {
	return &PhoneValidatorImpl{
		userService:  userService,
		adminService: adminService,
		auditService: auditService,
	}
}

// GetAdminIDByPhone returns the admin ID for a given phone number.
func (v *PhoneValidatorImpl) GetAdminIDByPhone(ctx context.Context, phoneNumber string) (uuid.UUID, error) {
	var empty uuid.UUID
	if v.adminService == nil {
		return empty, appErrors.ErrInternal
	}

	admin, err := v.adminService.GetAdminByPhone(ctx, phoneNumber)
	if err != nil {
		v.audit(ctx, phoneNumber, "admin_id_lookup", "failed", err.Error())
		// If not found, return ErrNotFound directly, but preserve the error type
		if errors.Is(err, appErrors.ErrNotFound) {
			return empty, appErrors.ErrNotFound
		}
		return empty, err
	}
	if admin == nil || !admin.IsActive {
		v.audit(ctx, phoneNumber, "admin_id_lookup", "failed", "admin not found or inactive")
		return empty, appErrors.ErrNotFound
	}

	v.audit(ctx, phoneNumber, "admin_id_lookup", "success", "")
	return admin.AdminID, nil
}

// GetUserIDByPhone returns the user ID for a given phone number.
func (v *PhoneValidatorImpl) GetUserIDByPhone(ctx context.Context, phoneNumber string) (uuid.UUID, error) {
	var empty uuid.UUID
	if v.userService == nil {
		return empty, appErrors.ErrInternal
	}

	user, err := v.userService.GetUserByPhone(ctx, phoneNumber)
	if err != nil {
		v.audit(ctx, phoneNumber, "user_id_lookup", "failed", err.Error())
		if errors.Is(err, appErrors.ErrNotFound) {
			return empty, appErrors.ErrNotFound
		}
		return empty, err
	}
	if user == nil || !user.IsActive {
		v.audit(ctx, phoneNumber, "user_id_lookup", "failed", "user not found or inactive")
		return empty, appErrors.ErrNotFound
	}

	v.audit(ctx, phoneNumber, "user_id_lookup", "success", "")
	return user.UserID, nil
}

// IsAdminPhoneRegistered checks if a phone number is registered as an active admin.
func (v *PhoneValidatorImpl) IsAdminPhoneRegistered(ctx context.Context, phoneNumber string) (bool, error) {
	if v.adminService == nil {
		return false, appErrors.ErrInternal
	}

	admin, err := v.adminService.GetAdminByPhone(ctx, phoneNumber)
	if err != nil {
		// If the error is "not found", treat as not registered; otherwise log error.
		if errors.Is(err, appErrors.ErrNotFound) {
			v.audit(ctx, phoneNumber, "admin_registered_check", "not_registered", "")
			return false, nil
		}
		v.audit(ctx, phoneNumber, "admin_registered_check", "failed", err.Error())
		return false, err
	}
	registered := admin != nil && admin.IsActive
	if registered {
		v.audit(ctx, phoneNumber, "admin_registered_check", "registered", "")
	} else {
		v.audit(ctx, phoneNumber, "admin_registered_check", "not_registered", "")
	}
	return registered, nil
}

// IsUserPhoneRegistered checks if a phone number is registered as an active user.
func (v *PhoneValidatorImpl) IsUserPhoneRegistered(ctx context.Context, phoneNumber string) (bool, error) {
	if v.userService == nil {
		return false, appErrors.ErrInternal
	}

	user, err := v.userService.GetUserByPhone(ctx, phoneNumber)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			v.audit(ctx, phoneNumber, "user_registered_check", "not_registered", "")
			return false, nil
		}
		v.audit(ctx, phoneNumber, "user_registered_check", "failed", err.Error())
		return false, err
	}
	registered := user != nil && user.IsActive
	if registered {
		v.audit(ctx, phoneNumber, "user_registered_check", "registered", "")
	} else {
		v.audit(ctx, phoneNumber, "user_registered_check", "not_registered", "")
	}
	return registered, nil
}

// audit is a helper to send audit logs for phone validation events.
func (v *PhoneValidatorImpl) audit(ctx context.Context, phoneNumber, action, status, message string) {
	if v.auditService == nil {
		return
	}
	ip, _ := ctx.Value("ip_address").(string)
	_ = v.auditService.LogAction(
		ctx,
		nil, // no transaction
		nil, // no company ID
		"phone_validator",
		action,
		"phone",
		nil, // no entity ID
		"system",
		nil, // no actor ID
		nil,
		nil,
		map[string]interface{}{
			"phone_number": phoneNumber,
			"status":       status,
			"message":      message,
			"ip":           ip,
		},
	)
}

// SetAdminService injects the admin service after creation (breaks circular dependency)
func (v *PhoneValidatorImpl) SetAdminService(adminService *AdminService) {
	v.adminService = adminService
}

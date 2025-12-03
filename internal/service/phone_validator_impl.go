package service

import (
	"auth-service/internal/util"
	"context"
	"errors"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type PhoneValidatorImpl struct {
	userService  *UserService
	adminService *AdminService
	logger       *zap.Logger
	initialized  bool
}

func NewPhoneValidator(userService *UserService, adminService *AdminService, logger *zap.Logger) *PhoneValidatorImpl {
	return &PhoneValidatorImpl{
		userService:  userService,
		adminService: adminService,
		logger:       logger,
		initialized:  adminService != nil,
	}
}

func (v *PhoneValidatorImpl) SetAdminService(adminService *AdminService) {
	v.adminService = adminService
	v.initialized = true
	v.logger.Debug("AdminService set on PhoneValidator")
}

func (v *PhoneValidatorImpl) GetAdminIDByPhone(ctx context.Context, phoneNumber string) (uuid.UUID, error) {
	var empty uuid.UUID

	if v.adminService == nil || !v.initialized {
		v.logger.Warn("Admin service not available for GetAdminIDByPhone")
		return empty, errors.New("admin service not available")
	}

	admin, err := v.adminService.GetAdminByPhone(ctx, phoneNumber)
	if err != nil {
		v.logger.Warn("Admin lookup failed",
			util.String("phone", phoneNumber),
			util.ErrorField(err),
		)
		return empty, err
	}

	if admin == nil || !admin.IsActive {
		return empty, errors.New("admin not found or inactive")
	}

	return admin.AdminID, nil
}

// Add this new method for user OTP service
func (v *PhoneValidatorImpl) GetUserIDByPhone(ctx context.Context, phoneNumber string) (uuid.UUID, error) {
	var empty uuid.UUID

	if v.userService == nil {
		v.logger.Warn("User service not available for GetUserIDByPhone")
		return empty, errors.New("user service not available")
	}

	user, err := v.userService.GetUserByPhone(ctx, phoneNumber)
	if err != nil {
		v.logger.Warn("User lookup failed",
			util.String("phone", phoneNumber),
			util.ErrorField(err),
		)
		return empty, err
	}

	if user == nil || !user.IsActive {
		return empty, errors.New("user not found or inactive")
	}

	return user.UserID, nil
}
func (v *PhoneValidatorImpl) IsAdminPhoneRegistered(ctx context.Context, phoneNumber string) (bool, error) {
	if v.adminService == nil || !v.initialized {
		v.logger.Warn("Admin service not available for admin phone check")
		return false, errors.New("admin service not available")
	}

	admin, err := v.adminService.GetAdminByPhone(ctx, phoneNumber)
	if err != nil {
		v.logger.Debug("Phone not found in admin table",
			util.String("phone", phoneNumber),
			util.ErrorField(err))
		return false, nil
	}

	return admin != nil && admin.IsActive, nil
}
func (v *PhoneValidatorImpl) IsUserPhoneRegistered(ctx context.Context, phoneNumber string) (bool, error) {
	if v.userService == nil || !v.initialized {
		v.logger.Warn("User service not available for user phone check")
		return false, errors.New("user service not available")
	}

	user, err := v.userService.GetUserByPhone(ctx, phoneNumber)
	if err != nil {
		v.logger.Debug("Phone not found in user table",
			util.String("phone", phoneNumber),
			util.ErrorField(err))
		return false, nil
	}

	return user != nil && user.IsActive, nil
}

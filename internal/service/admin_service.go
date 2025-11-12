package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/models"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/util"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AdminService handles admin related business logic
type AdminService struct {
	adminRepo      scylla.AdminRepository
	userRepo       scylla.UserRepository
	sessionService *SessionService
	otpService     *OTPService
	mpinService    *MPINService
	deviceService  *DeviceService
	hasher         *hashing.Hasher
	encryptionMgr  *encryption.EncryptionManager
	logProducer    *LogProducerService
	logger         *zap.Logger
}

// NewAdminService creates admin service with injected dependencies
func NewAdminService(
	adminRepo scylla.AdminRepository,
	userRepo scylla.UserRepository,
	sessionService *SessionService,
	otpService *OTPService,
	mpinService *MPINService,
	deviceService *DeviceService,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	logger *zap.Logger,
) *AdminService {
	return &AdminService{
		adminRepo:      adminRepo,
		userRepo:       userRepo,
		sessionService: sessionService,
		otpService:     otpService,
		mpinService:    mpinService,
		deviceService:  deviceService,
		hasher:         hasher,
		encryptionMgr:  encryptionMgr,
		logger:         logger,
	}
}

// SetLogProducerService sets Kafka log producer service
func (s *AdminService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}

// logAdminEvent logs an admin event to Kafka
func (s *AdminService) logAdminEvent(ctx context.Context, event *models.AdminLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceAdminEvent(ctx, event)
	}
}

// GeneratePhoneHash generates a hash of the phone number
func (s *AdminService) GeneratePhoneHash(phoneNumber string) string {
	normalized := strings.ReplaceAll(phoneNumber, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "(", "")
	normalized = strings.ReplaceAll(normalized, ")", "")

	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// InitializeOwner creates the first system owner
func (s *AdminService) InitializeOwner(ctx context.Context, phone string) (*models.AdminUser, error) {
	startTime := time.Now()

	exists, err := s.adminRepo.IsAdminOwnerExists(ctx)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to check owner existence",
			},
			Action:       "initialize_owner",
			Status:       "failed",
			ErrorCode:    "CHECK_OWNER_EXISTS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("failed to check owner existence: %w", err)
	}

	if exists {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Owner already exists",
			},
			Action:    "initialize_owner",
			Status:    "failed",
			ErrorCode: "OWNER_ALREADY_EXISTS",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("system already has an owner")
	}

	phoneHash := s.GeneratePhoneHash(phone)
	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to encrypt phone for owner",
			},
			Action:       "initialize_owner",
			Status:       "failed",
			ErrorCode:    "PHONE_ENCRYPTION_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("failed to encrypt phone: %w", err)
	}

	keyID, err := uuid.Parse(encryptedResult.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key ID: %w", err)
	}

	ownerID := uuid.New()
	owner := &models.AdminUser{
		AdminID:           ownerID,
		PhoneHash:         phoneHash,
		PhoneEncrypted:    encryptedResult.EncryptedValue,
		PhoneKeyID:        keyID,
		PhoneEncryptedDEK: encryptedResult.EncryptedDEK,
		AdminRoleLevel:    models.AdminRoleLevelOwner,
		AdminPermissions:  s.getOwnerPermissions(),
		AdminCreatedAt:    time.Now().UTC(),
		AdminCreatedBy:    ownerID,
		AdminUpdatedAt:    time.Now().UTC(),
		IsActive:          true,
		DataAccessScope:   []string{models.DataAccessGlobal},
		IPWhitelist:       []string{},
		FailedLoginAttempts: 0,
		LastLogin:         time.Time{},
	}

	if err := s.adminRepo.CreateAdmin(ctx, owner); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to create owner in database",
			},
			Action:       "initialize_owner",
			Status:       "failed",
			ErrorCode:    "CREATE_OWNER_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("failed to create owner: %w", err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Owner initialized successfully",
		},
		AdminID:   ownerID.String(),
		AdminRole: models.AdminRoleLevelOwner,
		Action:    "initialize_owner",
		Status:    "success",
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Owner initialized", util.String("admin_id", owner.AdminID.String()))

	return owner, nil
}

// ChangeOwnerPhone allows owner to update their phone
func (s *AdminService) ChangeOwnerPhone(ctx context.Context, ownerID uuid.UUID, newPhone string) error {
	startTime := time.Now()

	if ownerID == uuid.Nil {
		return fmt.Errorf("invalid owner ID")
	}
	if newPhone == "" {
		return fmt.Errorf("new phone cannot be empty")
	}

	owner, err := s.adminRepo.GetOwner(ctx)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to get owner",
			},
			AdminID:      ownerID.String(),
			Action:       "change_owner_phone",
			Status:       "failed",
			ErrorCode:    "GET_OWNER_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to get owner: %w", err)
	}

	if owner == nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Owner not found",
			},
			AdminID:      ownerID.String(),
			Action:       "change_owner_phone",
			Status:       "failed",
			ErrorCode:    "OWNER_NOT_FOUND",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("owner not found in system")
	}

	if owner.AdminID != ownerID {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized phone change attempt",
			},
			AdminID:      ownerID.String(),
			Action:       "change_owner_phone",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("unauthorized: only owner can change phone")
	}

	newPhoneHash := s.GeneratePhoneHash(newPhone)

	if owner.PhoneHash == newPhoneHash {
		return fmt.Errorf("new phone is the same as current phone")
	}

	existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, newPhoneHash)
	if err == nil && existingAdmin != nil && existingAdmin.AdminID != ownerID {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Phone already used by another admin",
			},
			AdminID:      ownerID.String(),
			Action:       "change_owner_phone",
			Status:       "failed",
			ErrorCode:    "PHONE_ALREADY_USED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("phone number is already used by another admin")
	}

	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, newPhone, "phone")
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to encrypt new phone",
			},
			AdminID:      ownerID.String(),
			Action:       "change_owner_phone",
			Status:       "failed",
			ErrorCode:    "PHONE_ENCRYPTION_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to encrypt new phone: %w", err)
	}

	keyID, err := uuid.Parse(encryptedResult.KeyID)
	if err != nil {
		return fmt.Errorf("failed to parse key ID: %w", err)
	}

	// ✅ FIXED: Use correct method name
	if err := s.adminRepo.UpdateAdminOwnerPhone(ctx, ownerID, newPhoneHash, encryptedResult.EncryptedValue, keyID, encryptedResult.EncryptedDEK); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update owner phone in database",
			},
			AdminID:      ownerID.String(),
			Action:       "change_owner_phone",
			Status:       "failed",
			ErrorCode:    "UPDATE_PHONE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to update owner phone: %w", err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Owner phone updated successfully",
		},
		AdminID:    ownerID.String(),
		AdminRole:  models.AdminRoleLevelOwner,
		Action:     "change_owner_phone",
		Status:     "success",
		Duration:   int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// InviteAdmin invites a user as admin
func (s *AdminService) InviteAdmin(ctx context.Context, phone string, roleLevel string, requesterID uuid.UUID, requesterRole string) (*models.AdminUser, error) {
	startTime := time.Now()

	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Requester not found",
			},
			AdminID:      requesterID.String(),
			Action:       "invite_admin",
			Status:       "failed",
			ErrorCode:    "REQUESTER_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("requester not found: %w", err)
	}

	if !requester.IsActive {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Requester is not active",
			},
			AdminID:      requesterID.String(),
			Action:       "invite_admin",
			Status:       "failed",
			ErrorCode:    "REQUESTER_INACTIVE",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("requester is not active")
	}

	if requester.IsEmployee() {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Employee cannot invite admins",
			},
			AdminID:      requesterID.String(),
			Action:       "invite_admin",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("employees cannot invite admins")
	}

	if requester.IsSuperEmployee() && roleLevel != models.AdminRoleLevelEmployee {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Super employee can only invite as employee",
			},
			AdminID:      requesterID.String(),
			Action:       "invite_admin",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("super employees can only invite as employee")
	}

	phoneHash := s.GeneratePhoneHash(phone)

	existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
	if err == nil && existingAdmin != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Phone already an admin",
			},
			AdminID:      requesterID.String(),
			Action:       "invite_admin",
			Status:       "failed",
			ErrorCode:    "PHONE_ALREADY_ADMIN",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("phone number is already an admin")
	}

	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to encrypt phone",
			},
			AdminID:      requesterID.String(),
			Action:       "invite_admin",
			Status:       "failed",
			ErrorCode:    "PHONE_ENCRYPTION_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("failed to encrypt phone: %w", err)
	}

	keyID, err := uuid.Parse(encryptedResult.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key ID: %w", err)
	}

	permissions := s.getPermissionsForRole(roleLevel)

	adminID := uuid.New()
	now := time.Now().UTC()
	admin := &models.AdminUser{
		AdminID:             adminID,
		PhoneHash:           phoneHash,
		PhoneEncrypted:      encryptedResult.EncryptedValue,
		PhoneKeyID:          keyID,
		PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
		AdminRoleLevel:      roleLevel,
		AdminPermissions:    permissions,
		AdminCreatedAt:      now,
		AdminCreatedBy:      requesterID,
		AdminUpdatedAt:      now,
		IsActive:            true,
		DataAccessScope:     s.getDefaultDataAccessScope(roleLevel),
		IPWhitelist:         []string{},
		FailedLoginAttempts: 0,
		LastLogin:           time.Time{},
	}

	if err := s.adminRepo.CreateAdmin(ctx, admin); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to create admin in database",
			},
			AdminID:      requesterID.String(),
			Action:       "invite_admin",
			Status:       "failed",
			ErrorCode:    "CREATE_ADMIN_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("failed to invite user as admin: %w", err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin invited successfully",
		},
		AdminID:      adminID.String(),
		AdminRole:    roleLevel,
		TargetUserID: phone,
		Action:       "invite_admin",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})

	return admin, nil
}

// GetAdminByPhone retrieves admin by phone
func (s *AdminService) GetAdminByPhone(ctx context.Context, phone string) (*models.AdminUser, error) {
	phoneHash := s.GeneratePhoneHash(phone)
	return s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
}

// AuthenticateAdmin authenticates an admin by phone
func (s *AdminService) AuthenticateAdmin(ctx context.Context, phone string) (*models.AdminUser, error) {
	startTime := time.Now()

	phoneHash := s.GeneratePhoneHash(phone)
	admin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Admin authentication failed",
			},
			Action:       "authenticate_admin",
			Status:       "failed",
			ErrorCode:    "AUTHENTICATION_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	if !admin.IsActive {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Admin account deactivated",
			},
			AdminID:      admin.AdminID.String(),
			Action:       "authenticate_admin",
			Status:       "failed",
			ErrorCode:    "ACCOUNT_DEACTIVATED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("admin account is deactivated")
	}

	// ✅ FIXED: Use correct method name
	if err := s.adminRepo.UpdateAdminLastLogin(ctx, admin.AdminID); err != nil {
		s.logger.Warn("Failed to update last login",
			util.String("admin_id", admin.AdminID.String()),
			util.ErrorField(err),
		)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin authenticated successfully",
		},
		AdminID:    admin.AdminID.String(),
		AdminRole:  admin.AdminRoleLevel,
		Action:     "authenticate_admin",
		Status:     "success",
		Duration:   int64(time.Since(startTime).Milliseconds()),
	})

	return admin, nil
}

// AuthenticateAdminWithSession authenticates admin and creates session
func (s *AdminService) AuthenticateAdminWithSession(ctx context.Context, phone string, deviceID string, ipAddress string) (*models.AdminUser, string, error) {
	startTime := time.Now()

	admin, err := s.AuthenticateAdmin(ctx, phone)
	if err != nil {
		return nil, "", err
	}

	sessionReq := &CreateAdminSessionRequest{
		AdminID:           admin.AdminID,
		AdminRoleLevel:    admin.AdminRoleLevel,
		DeviceID:          deviceID,
		DeviceFingerprint: "admin-web",
		IPAddress:         ipAddress,
		Permissions:       admin.AdminPermissions,
	}

	session, err := s.sessionService.CreateAdminSession(ctx, sessionReq)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to create admin session",
			},
			AdminID:      admin.AdminID.String(),
			Action:       "authenticate_admin_with_session",
			Status:       "failed",
			ErrorCode:    "CREATE_SESSION_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, "", fmt.Errorf("failed to create admin session: %w", err)
	}

	// ✅ FIXED: Use correct method name
	if err := s.adminRepo.UpdateAdminLastLogin(ctx, admin.AdminID); err != nil {
		s.logger.Warn("Failed to update last login",
			util.String("admin_id", admin.AdminID.String()),
			util.ErrorField(err),
		)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin authenticated with session successfully",
		},
		AdminID:    admin.AdminID.String(),
		AdminRole:  admin.AdminRoleLevel,
		Action:     "authenticate_admin_with_session",
		Status:     "success",
		Duration:   int64(time.Since(startTime).Milliseconds()),
	})

	return admin, session.SessionToken, nil
}

// PromoteAdmin promotes an admin to higher role
func (s *AdminService) PromoteAdmin(ctx context.Context, adminID uuid.UUID, newRole string, promotedBy uuid.UUID) error {
	startTime := time.Now()

	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Admin not found for promotion",
			},
			AdminID:      promotedBy.String(),
			Action:       "promote_admin",
			Status:       "failed",
			ErrorCode:    "ADMIN_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("admin not found: %w", err)
	}

	promoter, err := s.adminRepo.GetAdminByID(ctx, promotedBy)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Promoter not found",
			},
			AdminID:      promotedBy.String(),
			Action:       "promote_admin",
			Status:       "failed",
			ErrorCode:    "PROMOTER_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("promoter not found: %w", err)
	}

	if !promoter.CanPromoteToRole(newRole) {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized promotion attempt",
			},
			AdminID:      promotedBy.String(),
			Action:       "promote_admin",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("unauthorized: cannot promote to %s role", newRole)
	}

	oldRole := admin.AdminRoleLevel

	if err := s.adminRepo.UpdateAdminRoleLevel(ctx, adminID, newRole, promotedBy); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update admin role",
			},
			AdminID:      promotedBy.String(),
			Action:       "promote_admin",
			Status:       "failed",
			ErrorCode:    "UPDATE_ROLE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to promote admin: %w", err)
	}

	newPermissions := s.getPermissionsForRole(newRole)
	if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, newPermissions); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update admin permissions",
			},
			AdminID:      promotedBy.String(),
			Action:       "promote_admin",
			Status:       "failed",
			ErrorCode:    "UPDATE_PERMISSIONS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to update permissions: %w", err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin promoted successfully",
		},
		AdminID:      adminID.String(),
		AdminRole:    newRole,
		TargetUserID: adminID.String(),
		Action:       "promote_admin",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"old_role": oldRole,
			"new_role": newRole,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// RemoveAdmin removes an admin (soft delete)
func (s *AdminService) RemoveAdmin(ctx context.Context, adminID uuid.UUID, removedBy uuid.UUID) error {
	startTime := time.Now()

	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Admin not found for removal",
			},
			AdminID:      removedBy.String(),
			Action:       "remove_admin",
			Status:       "failed",
			ErrorCode:    "ADMIN_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("admin not found: %w", err)
	}

	remover, err := s.adminRepo.GetAdminByID(ctx, removedBy)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Remover not found",
			},
			AdminID:      removedBy.String(),
			Action:       "remove_admin",
			Status:       "failed",
			ErrorCode:    "REMOVER_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("remover not found: %w", err)
	}

	if !remover.CanManageEmployee(admin.AdminRoleLevel) {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized removal attempt",
			},
			AdminID:      removedBy.String(),
			Action:       "remove_admin",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("unauthorized: cannot remove admin with role %s", admin.AdminRoleLevel)
	}

	if admin.IsOwner() {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Cannot remove owner admin",
			},
			AdminID:      removedBy.String(),
			Action:       "remove_admin",
			Status:       "failed",
			ErrorCode:    "CANNOT_REMOVE_OWNER",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("cannot remove owner admin")
	}

	if err := s.adminRepo.RemoveAdmin(ctx, adminID, removedBy); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to remove admin",
			},
			AdminID:      removedBy.String(),
			Action:       "remove_admin",
			Status:       "failed",
			ErrorCode:    "REMOVE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to remove admin: %w", err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin removed successfully",
		},
		AdminID:      adminID.String(),
		AdminRole:    admin.AdminRoleLevel,
		TargetUserID: adminID.String(),
		Action:       "remove_admin",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// DeactivateAdmin deactivates an admin temporarily
func (s *AdminService) DeactivateAdmin(ctx context.Context, adminID uuid.UUID, deactivatedBy uuid.UUID) error {
	startTime := time.Now()

	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Admin not found for deactivation",
			},
			AdminID:      deactivatedBy.String(),
			Action:       "deactivate_admin",
			Status:       "failed",
			ErrorCode:    "ADMIN_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("admin not found: %w", err)
	}

	if !admin.IsActive {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Admin already inactive",
			},
			AdminID:      deactivatedBy.String(),
			Action:       "deactivate_admin",
			Status:       "failed",
			ErrorCode:    "ALREADY_INACTIVE",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("admin is already inactive")
	}

	if admin.IsOwner() {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Cannot deactivate owner admin",
			},
			AdminID:      deactivatedBy.String(),
			Action:       "deactivate_admin",
			Status:       "failed",
			ErrorCode:    "CANNOT_DEACTIVATE_OWNER",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("cannot deactivate owner admin")
	}

	if err := s.adminRepo.DeactivateAdmin(ctx, adminID); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to deactivate admin",
			},
			AdminID:      deactivatedBy.String(),
			Action:       "deactivate_admin",
			Status:       "failed",
			ErrorCode:    "DEACTIVATE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to deactivate admin: %w", err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin deactivated successfully",
		},
		AdminID:      adminID.String(),
		AdminRole:    admin.AdminRoleLevel,
		TargetUserID: adminID.String(),
		Action:       "deactivate_admin",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// ActivateAdmin reactivates a deactivated admin
func (s *AdminService) ActivateAdmin(ctx context.Context, adminID uuid.UUID, activatedBy uuid.UUID) error {
	startTime := time.Now()

	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Admin not found for activation",
			},
			AdminID:      activatedBy.String(),
			Action:       "activate_admin",
			Status:       "failed",
			ErrorCode:    "ADMIN_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("admin not found: %w", err)
	}

	if admin.IsActive {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Admin already active",
			},
			AdminID:      activatedBy.String(),
			Action:       "activate_admin",
			Status:       "failed",
			ErrorCode:    "ALREADY_ACTIVE",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("admin is already active")
	}

	if err := s.adminRepo.ActivateAdmin(ctx, adminID); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to activate admin",
			},
			AdminID:      activatedBy.String(),
			Action:       "activate_admin",
			Status:       "failed",
			ErrorCode:    "ACTIVATE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to activate admin: %w", err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin activated successfully",
		},
		AdminID:      adminID.String(),
		AdminRole:    admin.AdminRoleLevel,
		TargetUserID: adminID.String(),
		Action:       "activate_admin",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Duration:     int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// GetAdmin retrieves admin by ID
func (s *AdminService) GetAdmin(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, error) {
	return s.adminRepo.GetAdminByID(ctx, adminID)
}

// GetActiveAdmins retrieves all active admins
func (s *AdminService) GetActiveAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error) {
	return s.adminRepo.GetActiveAdmins(ctx, limit)
}

// GetAdminsByRole retrieves admins by role level
func (s *AdminService) GetAdminsByRole(ctx context.Context, roleLevel string) ([]*models.AdminUser, error) {
	return s.adminRepo.GetAdminsByRole(ctx, roleLevel)
}

// UpdateAdminPermissions updates admin permissions
func (s *AdminService) UpdateAdminPermissions(ctx context.Context, adminID uuid.UUID, permissions []string, updatedBy uuid.UUID) error {
	startTime := time.Now()

	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Admin not found for permission update",
			},
			AdminID:      updatedBy.String(),
			Action:       "update_admin_permissions",
			Status:       "failed",
			ErrorCode:    "ADMIN_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("admin not found: %w", err)
	}

	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Updater not found",
			},
			AdminID:      updatedBy.String(),
			Action:       "update_admin_permissions",
			Status:       "failed",
			ErrorCode:    "UPDATER_NOT_FOUND",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("updater not found: %w", err)
	}

	if !updater.CanManageEmployee(admin.AdminRoleLevel) {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized permission update attempt",
			},
			AdminID:      updatedBy.String(),
			Action:       "update_admin_permissions",
			Status:       "failed",
			ErrorCode:    "UNAUTHORIZED",
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("unauthorized: cannot update permissions for %s role", admin.AdminRoleLevel)
	}

	oldPermissions := admin.AdminPermissions

	if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, permissions); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update admin permissions",
			},
			AdminID:      updatedBy.String(),
			Action:       "update_admin_permissions",
			Status:       "failed",
			ErrorCode:    "UPDATE_PERMISSIONS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to update permissions: %w", err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin permissions updated successfully",
		},
		AdminID:      adminID.String(),
		AdminRole:    admin.AdminRoleLevel,
		TargetUserID: adminID.String(),
		Action:       "update_admin_permissions",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"old_permissions": oldPermissions,
			"new_permissions": permissions,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// RecordAdminLogin records admin login attempt
func (s *AdminService) RecordAdminLogin(ctx context.Context, adminID uuid.UUID) error {
	startTime := time.Now()

	// ✅ FIXED: Use correct method name
	if err := s.adminRepo.UpdateAdminLastLogin(ctx, adminID); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Failed to record admin login",
			},
			AdminID:      adminID.String(),
			Action:       "record_admin_login",
			Status:       "failed",
			ErrorCode:    "RECORD_LOGIN_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to record login: %w", err)
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Admin login recorded successfully",
		},
		AdminID:    adminID.String(),
		Action:     "record_admin_login",
		Status:     "success",
		Duration:   int64(time.Since(startTime).Milliseconds()),
	})

	// ✅ FIXED: Use correct method name
	if err := s.adminRepo.ResetAdminFailedLoginAttempts(ctx, adminID); err != nil {
		s.logger.Warn("Failed to reset login attempts",
			util.String("admin_id", adminID.String()),
			util.ErrorField(err),
		)
	}

	return nil
}

// RecordFailedLogin records failed login attempt and checks for lockout
func (s *AdminService) RecordFailedLogin(ctx context.Context, adminID uuid.UUID) (bool, int, error) {
	startTime := time.Now()

	// ✅ FIXED: Use correct method name
	attempts, err := s.adminRepo.IncrementAdminFailedLoginAttempts(ctx, adminID)
	if err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to record failed login",
			},
			AdminID:      adminID.String(),
			Action:       "record_failed_login",
			Status:       "failed",
			ErrorCode:    "RECORD_FAILED_LOGIN_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return false, 0, fmt.Errorf("failed to increment attempts: %w", err)
	}

	const maxAttempts = 5
	shouldLockout := attempts >= maxAttempts

	if shouldLockout {
		if err := s.adminRepo.DeactivateAdmin(ctx, adminID); err != nil {
			s.logger.Warn("Failed to deactivate admin after lockout",
				util.String("admin_id", adminID.String()),
				util.ErrorField(err),
			)
			s.logAdminEvent(ctx, &models.AdminLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   "admin",
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: "production",
					Version:     "v1.0.0",
					Level:       "warning",
					Message:     "Failed to deactivate admin after lockout",
				},
				AdminID:      adminID.String(),
				Action:       "admin_lockout",
				Status:       "failed",
				ErrorCode:    "DEACTIVATE_AFTER_LOCKOUT_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			})
		} else {
			s.logAdminEvent(ctx, &models.AdminLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   "admin",
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: "production",
					Version:     "v1.0.0",
					Level:       "warning",
					Message:     "Admin locked out due to failed attempts",
				},
				AdminID:    adminID.String(),
				Action:     "admin_lockout",
				Status:     "success",
				Duration:   int64(time.Since(startTime).Milliseconds()),
			})
		}
	}

	s.logAdminEvent(ctx, &models.AdminLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "admin",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "warning",
			Message:     "Admin failed login attempt",
		},
		AdminID:    adminID.String(),
		Action:     "failed_login_attempt",
		Status:     "success",
		Duration:   int64(time.Since(startTime).Milliseconds()),
	})

	return shouldLockout, attempts, nil
}

// ===== HELPER METHODS =====

// getDefaultDataAccessScope returns default data access scope for role
func (s *AdminService) getDefaultDataAccessScope(roleLevel string) []string {
	switch roleLevel {
	case models.AdminRoleLevelOwner, models.AdminRoleLevelSuperEmployee:
		return []string{models.DataAccessGlobal}
	case models.AdminRoleLevelEmployee:
		return []string{models.DataAccessGlobal}
	default:
		return []string{models.DataAccessGlobal}
	}
}

// getOwnerPermissions returns all permissions for owner
func (s *AdminService) getOwnerPermissions() []string {
	return []string{
		models.PermissionReadUsers,
		models.PermissionWriteUsers,
		models.PermissionBanUsers,
		models.PermissionUnbanUsers,
		models.PermissionVerifyKYC,
		models.PermissionManageAdmins,
		models.PermissionViewAuditLog,
		models.PermissionExportData,
		models.PermissionDeleteUsers,
		models.PermissionSystemConfig,
	}
}

// getPermissionsForRole returns permissions based on role
func (s *AdminService) getPermissionsForRole(roleLevel string) []string {
	switch roleLevel {
	case models.AdminRoleLevelOwner:
		return s.getOwnerPermissions()

	case models.AdminRoleLevelSuperEmployee:
		return []string{
			models.PermissionReadUsers,
			models.PermissionWriteUsers,
			models.PermissionBanUsers,
			models.PermissionUnbanUsers,
			models.PermissionVerifyKYC,
			models.PermissionManageAdmins,
			models.PermissionViewAuditLog,
		}

	case models.AdminRoleLevelEmployee:
		return []string{
			models.PermissionReadUsers,
			models.PermissionWriteUsers,
			models.PermissionVerifyKYC,
			models.PermissionViewAuditLog,
		}

	default:
		return []string{}
	}
}

// HealthChecka verifies admin service health
func (s *AdminService) HealthCheck(ctx context.Context) error {
	return s.adminRepo.HealthCheck(ctx)
}

// GetStats returns admin service statistics
func (s *AdminService) GetStats(ctx context.Context) (map[string]interface{}, error) {
	return s.adminRepo.GetRepositoryStats(ctx)
}
// Add this method to AdminService
func (s *AdminService) GetInactiveAdmins(ctx context.Context, limit int) ([]*models.AdminUser, error) {
    // Get all admins and filter inactive ones
    allAdmins, err := s.adminRepo.GetAllAdmins(ctx, limit)
    if err != nil {
        return nil, err
    }
    
    var inactiveAdmins []*models.AdminUser
    for _, admin := range allAdmins {
        if !admin.IsActive {
            inactiveAdmins = append(inactiveAdmins, admin)
        }
    }
    
    return inactiveAdmins, nil
}
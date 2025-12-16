package service

import (
	"auth-service/internal/repository/postgres"
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
	companyRepo    postgres.CompanyRepository  
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
	companyRepo postgres.CompanyRepository, 
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
		companyRepo:    companyRepo,
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

// // GeneratePhoneHash generates a hash of the phone number
// func (s *AdminService) GeneratePhoneHash(phoneNumber string) string {
// 	normalized := strings.ReplaceAll(phoneNumber, " ", "")
// 	normalized = strings.ReplaceAll(normalized, "-", "")
// 	normalized = strings.ReplaceAll(normalized, "(", "")
// 	normalized = strings.ReplaceAll(normalized, ")", "")

// 	hash := sha256.Sum256([]byte(normalized))
// 	return hex.EncodeToString(hash[:])
// }

// // InitializeOwner creates the first system owner
// func (s *AdminService) InitializeOwner(ctx context.Context, phone string) (*models.AdminUser, error) {
// 	startTime := time.Now()

// 	exists, err := s.adminRepo.IsAdminOwnerExists(ctx)
// 	if err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Failed to check owner existence",
// 			},
// 			Action:       "initialize_owner",
// 			Status:       "failed",
// 			ErrorCode:    "CHECK_OWNER_EXISTS_FAILED",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return nil, fmt.Errorf("failed to check owner existence: %w", err)
// 	}

// 	if exists {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "warning",
// 				Message:     "Owner already exists",
// 			},
// 			Action:    "initialize_owner",
// 			Status:    "failed",
// 			ErrorCode: "OWNER_ALREADY_EXISTS",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return nil, fmt.Errorf("system already has an owner")
// 	}

// 	phoneHash := s.GeneratePhoneHash(phone)
// 	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
// 	if err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Failed to encrypt phone for owner",
// 			},
// 			Action:       "initialize_owner",
// 			Status:       "failed",
// 			ErrorCode:    "PHONE_ENCRYPTION_FAILED",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return nil, fmt.Errorf("failed to encrypt phone: %w", err)
// 	}

// 	keyID, err := uuid.Parse(encryptedResult.KeyID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse key ID: %w", err)
// 	}

// 	ownerID := uuid.New()
// 	owner := &models.AdminUser{
// 		AdminID:             ownerID,
// 		PhoneHash:           phoneHash,
// 		PhoneEncrypted:      encryptedResult.EncryptedValue,
// 		PhoneKeyID:          keyID,
// 		PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
// 		AdminRoleMask:       models.RoleMaskOwner,
// 		AdminPermissionMask: s.getOwnerPermissions(),
// 		AdminCreatedAt:      time.Now().UTC(),
// 		AdminCreatedBy:      ownerID,
// 		AdminUpdatedAt:      time.Now().UTC(),
// 		IsActive:            true,
// 		DataAccessScope:     []string{models.DataAccessGlobal},
// 		IPWhitelist:         []string{},
// 		FailedLoginAttempts: 0,
// 		LastLogin:           time.Time{},
// 	}

// 	if err := s.adminRepo.CreateAdmin(ctx, owner); err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Failed to create owner in database",
// 			},
// 			Action:       "initialize_owner",
// 			Status:       "failed",
// 			ErrorCode:    "CREATE_OWNER_FAILED",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return nil, fmt.Errorf("failed to create owner: %w", err)
// 	}

// 	s.logAdminEvent(ctx, &models.AdminLogEvent{
// 		LogEnvelope: models.LogEnvelope{
// 			EventID:     uuid.New().String(),
// 			EventType:   "admin",
// 			ServiceName: "auth-service",
// 			Timestamp:   time.Now(),
// 			Environment: "production",
// 			Version:     "v1.0.0",
// 			Level:       "info",
// 			Message:     "Owner initialized successfully",
// 		},
// 		AdminID:   ownerID.String(),
// 		AdminRole: "owner",
// 		Action:    "initialize_owner",
// 		Status:    "success",
// 		Duration:  int64(time.Since(startTime).Milliseconds()),
// 	})

// 	s.logger.Info("Owner initialized", util.String("admin_id", owner.AdminID.String()))

// 	return owner, nil
// }

// // ChangeAdminPhone allows admin to update phone number based on hierarchy
// func (s *AdminService) ChangeAdminPhone(ctx context.Context, targetAdminID uuid.UUID, newPhone string, requesterID uuid.UUID) error {
// 	startTime := time.Now()

// 	if targetAdminID == uuid.Nil {
// 		return fmt.Errorf("invalid target admin ID")
// 	}
// 	if newPhone == "" {
// 		return fmt.Errorf("new phone cannot be empty")
// 	}
// 	if requesterID == uuid.Nil {
// 		return fmt.Errorf("invalid requester ID")
// 	}

// 	// Get requester admin
// 	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
// 	if err != nil {
// 		return fmt.Errorf("requester not found: %w", err)
// 	}

// 	// Get target admin
// 	targetAdmin, err := s.adminRepo.GetAdminByID(ctx, targetAdminID)
// 	if err != nil {
// 		return fmt.Errorf("target admin not found: %w", err)
// 	}

// 	// Check hierarchy rules
// 	if !s.canChangePhone(requester, targetAdmin) {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "warning",
// 				Message:     "Unauthorized phone change attempt",
// 			},
// 			AdminID:   requesterID.String(),
// 			TargetUserID: targetAdminID.String(),
// 			Action:    "change_admin_phone",
// 			Status:    "failed",
// 			ErrorCode: "UNAUTHORIZED",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("unauthorized: cannot change phone for this admin")
// 	}

// 	newPhoneHash := s.GeneratePhoneHash(newPhone)

// 	// Check if new phone is already used by another admin
// 	existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, newPhoneHash)
// 	if err == nil && existingAdmin != nil && existingAdmin.AdminID != targetAdminID {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "warning",
// 				Message:     "Phone already used by another admin",
// 			},
// 			AdminID:   requesterID.String(),
// 			TargetUserID: targetAdminID.String(),
// 			Action:    "change_admin_phone",
// 			Status:    "failed",
// 			ErrorCode: "PHONE_ALREADY_USED",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("phone number is already used by another admin")
// 	}

// 	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, newPhone, "phone")
// 	if err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Failed to encrypt new phone",
// 			},
// 			AdminID:      requesterID.String(),
// 			TargetUserID: targetAdminID.String(),
// 			Action:       "change_admin_phone",
// 			Status:       "failed",
// 			ErrorCode:    "PHONE_ENCRYPTION_FAILED",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("failed to encrypt new phone: %w", err)
// 	}

// 	keyID, err := uuid.Parse(encryptedResult.KeyID)
// 	if err != nil {
// 		return fmt.Errorf("failed to parse key ID: %w", err)
// 	}

// 	if err := s.adminRepo.UpdateAdminPhone(ctx, targetAdminID, newPhoneHash, encryptedResult.EncryptedValue, keyID, encryptedResult.EncryptedDEK); err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Failed to update admin phone in database",
// 			},
// 			AdminID:      requesterID.String(),
// 			TargetUserID: targetAdminID.String(),
// 			Action:       "change_admin_phone",
// 			Status:       "failed",
// 			ErrorCode:    "UPDATE_PHONE_FAILED",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("failed to update admin phone: %w", err)
// 	}

// 	s.logAdminEvent(ctx, &models.AdminLogEvent{
// 		LogEnvelope: models.LogEnvelope{
// 			EventID:     uuid.New().String(),
// 			EventType:   "admin",
// 			ServiceName: "auth-service",
// 			Timestamp:   time.Now(),
// 			Environment: "production",
// 			Version:     "v1.0.0",
// 			Level:       "info",
// 			Message:     "Admin phone updated successfully",
// 		},
// 		AdminID:   requesterID.String(),
// 		TargetUserID: targetAdminID.String(),
// 		AdminRole: requester.GetRoleString(),
// 		Action:    "change_admin_phone",
// 		Status:    "success",
// 		Duration:  int64(time.Since(startTime).Milliseconds()),
// 	})

// 	return nil
// }

// canChangePhone checks hierarchy rules for phone changes
func (s *AdminService) canChangePhone(requester, target *models.AdminUser) bool {
	// Anyone can change their own phone
	if requester.AdminID == target.AdminID {
		return true
	}

	// Owner can change anyone's phone
	if requester.IsOwner() {
		return true
	}

	// Super employee can change employee phones
	if requester.IsSuperEmployee() && target.IsEmployee() {
		return true
	}

	// Employee can only change their own phone
	return false
}

// // InviteAdmin invites a user as admin
// func (s *AdminService) InviteAdmin(ctx context.Context, phone string, roleMask uint64, requesterID uuid.UUID) (*models.AdminUser, error) {
// 	startTime := time.Now()

// 	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
// 	if err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Requester not found",
// 			},
// 			AdminID:      requesterID.String(),
// 			Action:       "invite_admin",
// 			Status:       "failed",
// 			ErrorCode:    "REQUESTER_NOT_FOUND",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return nil, fmt.Errorf("requester not found: %w", err)
// 	}

// 	if !requester.IsActive {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "warning",
// 				Message:     "Requester is not active",
// 			},
// 			AdminID:   requesterID.String(),
// 			Action:    "invite_admin",
// 			Status:    "failed",
// 			ErrorCode: "REQUESTER_INACTIVE",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return nil, fmt.Errorf("requester is not active")
// 	}

// 	if requester.IsEmployee() {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "warning",
// 				Message:     "Employee cannot invite admins",
// 			},
// 			AdminID:   requesterID.String(),
// 			Action:    "invite_admin",
// 			Status:    "failed",
// 			ErrorCode: "UNAUTHORIZED",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return nil, fmt.Errorf("employees cannot invite admins")
// 	}

// 	// Check if requester can invite to this role
// 	if !requester.CanPromoteToRole(roleMask) {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "warning",
// 				Message:     "Cannot invite to this role level",
// 			},
// 			AdminID:   requesterID.String(),
// 			Action:    "invite_admin",
// 			Status:    "failed",
// 			ErrorCode: "UNAUTHORIZED",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return nil, fmt.Errorf("cannot invite to this role level")
// 	}

// 	phoneHash := s.GeneratePhoneHash(phone)

// 	existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
// 	if err == nil && existingAdmin != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "warning",
// 				Message:     "Phone already an admin",
// 			},
// 			AdminID:   requesterID.String(),
// 			Action:    "invite_admin",
// 			Status:    "failed",
// 			ErrorCode: "PHONE_ALREADY_ADMIN",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return nil, fmt.Errorf("phone number is already an admin")
// 	}

// 	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
// 	if err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Failed to encrypt phone",
// 			},
// 			AdminID:      requesterID.String(),
// 			Action:       "invite_admin",
// 			Status:       "failed",
// 			ErrorCode:    "PHONE_ENCRYPTION_FAILED",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return nil, fmt.Errorf("failed to encrypt phone: %w", err)
// 	}

// 	keyID, err := uuid.Parse(encryptedResult.KeyID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse key ID: %w", err)
// 	}

// 	permissions := s.getPermissionsForRole(roleMask)

// 	adminID := uuid.New()
// 	now := time.Now().UTC()
// 	admin := &models.AdminUser{
// 		AdminID:             adminID,
// 		PhoneHash:           phoneHash,
// 		PhoneEncrypted:      encryptedResult.EncryptedValue,
// 		PhoneKeyID:          keyID,
// 		PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
// 		AdminRoleMask:       roleMask,
// 		AdminPermissionMask: permissions,
// 		AdminCreatedAt:      now,
// 		AdminCreatedBy:      requesterID,
// 		AdminUpdatedAt:      now,
// 		IsActive:            true,
// 		DataAccessScope:     s.getDefaultDataAccessScope(roleMask),
// 		IPWhitelist:         []string{},
// 		FailedLoginAttempts: 0,
// 		LastLogin:           time.Time{},
// 	}

// 	if err := s.adminRepo.CreateAdmin(ctx, admin); err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Failed to create admin in database",
// 			},
// 			AdminID:      requesterID.String(),
// 			Action:       "invite_admin",
// 			Status:       "failed",
// 			ErrorCode:    "CREATE_ADMIN_FAILED",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return nil, fmt.Errorf("failed to invite user as admin: %w", err)
// 	}

// 	s.logAdminEvent(ctx, &models.AdminLogEvent{
// 		LogEnvelope: models.LogEnvelope{
// 			EventID:     uuid.New().String(),
// 			EventType:   "admin",
// 			ServiceName: "auth-service",
// 			Timestamp:   time.Now(),
// 			Environment: "production",
// 			Version:     "v1.0.0",
// 			Level:       "info",
// 			Message:     "Admin invited successfully",
// 		},
// 		AdminID:      adminID.String(),
// 		AdminRole:    admin.GetRoleString(),
// 		TargetUserID: phone,
// 		Action:       "invite_admin",
// 		ResourceType: "admin_user",
// 		ResourceID:   adminID.String(),
// 		Status:       "success",
// 		Duration:     int64(time.Since(startTime).Milliseconds()),
// 	})

// 	return admin, nil
// }

// InviteAdmin invites a user as admin
func (s *AdminService) InviteAdmin(ctx context.Context, phone string, roleMask uint64, requesterID uuid.UUID) (*models.AdminUser, error) {
    startTime := time.Now()

    // BLOCK INVITING AS OWNER
    if roleMask == models.RoleMaskOwner {
        s.logAdminEvent(ctx, &models.AdminLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "admin",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "error",
                Message:     "Cannot invite user as owner",
            },
            AdminID:      requesterID.String(),
            Action:       "invite_admin",
            Status:       "failed",
            ErrorCode:    "CANNOT_INVITE_AS_OWNER",
            ErrorMessage: "Cannot invite user as owner. Owner can only be created via system initialization.",
            Duration:     int64(time.Since(startTime).Milliseconds()),
        })
        return nil, fmt.Errorf("cannot invite user as owner. Owner can only be created via system initialization")
    }

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
            AdminID:   requesterID.String(),
            Action:    "invite_admin",
            Status:    "failed",
            ErrorCode: "REQUESTER_INACTIVE",
            Duration:  int64(time.Since(startTime).Milliseconds()),
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
            AdminID:   requesterID.String(),
            Action:    "invite_admin",
            Status:    "failed",
            ErrorCode: "UNAUTHORIZED",
            Duration:  int64(time.Since(startTime).Milliseconds()),
        })
        return nil, fmt.Errorf("employees cannot invite admins")
    }

    // Check if requester can invite to this role
    if !requester.CanPromoteToRole(roleMask) {
        s.logAdminEvent(ctx, &models.AdminLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "admin",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "warning",
                Message:     "Cannot invite to this role level",
            },
            AdminID:   requesterID.String(),
            Action:    "invite_admin",
            Status:    "failed",
            ErrorCode: "UNAUTHORIZED",
            Duration:  int64(time.Since(startTime).Milliseconds()),
        })
        return nil, fmt.Errorf("cannot invite to this role level")
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
            AdminID:   requesterID.String(),
            Action:    "invite_admin",
            Status:    "failed",
            ErrorCode: "PHONE_ALREADY_ADMIN",
            Duration:  int64(time.Since(startTime).Milliseconds()),
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

    permissions := s.getPermissionsForRole(roleMask)

    adminID := uuid.New()
    now := time.Now().UTC()
    admin := &models.AdminUser{
        AdminID:             adminID,
        PhoneHash:           phoneHash,
        PhoneEncrypted:      encryptedResult.EncryptedValue,
        PhoneKeyID:          keyID,
        PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
        AdminRoleMask:       roleMask,
        AdminPermissionMask: permissions,
        AdminCreatedAt:      now,
        AdminCreatedBy:      requesterID,
        AdminUpdatedAt:      now,
        IsActive:            true,
        DataAccessScope:     s.getDefaultDataAccessScope(roleMask),
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
        AdminRole:    admin.GetRoleString(),
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
			AdminID:   admin.AdminID.String(),
			Action:    "authenticate_admin",
			Status:    "failed",
			ErrorCode: "ACCOUNT_DEACTIVATED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
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
		AdminID:   admin.AdminID.String(),
		AdminRole: admin.GetRoleString(),
		Action:    "authenticate_admin",
		Status:    "success",
		Duration:  int64(time.Since(startTime).Milliseconds()),
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
		AdminRoleMask:     admin.AdminRoleMask,
		DeviceID:          deviceID,
		DeviceFingerprint: "admin-web",
		IPAddress:         ipAddress,
		PermissionMask:    admin.AdminPermissionMask,
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
		AdminID:   admin.AdminID.String(),
		AdminRole: admin.GetRoleString(),
		Action:    "authenticate_admin_with_session",
		Status:    "success",
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	return admin, session.SessionToken, nil
}
// PromoteAdmin promotes an admin to higher role
func (s *AdminService) PromoteAdmin(ctx context.Context, adminID uuid.UUID, newRoleMask uint64, promotedBy uuid.UUID) error {
    startTime := time.Now()

    // BLOCK ANY ATTEMPT TO PROMOTE TO OWNER (ROLE MASK 1)
    if newRoleMask == models.RoleMaskOwner {
        s.logAdminEvent(ctx, &models.AdminLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "admin",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "error",
                Message:     "Attempt to promote to owner is forbidden",
            },
            AdminID:      promotedBy.String(),
            Action:       "promote_admin",
            Status:       "failed",
            ErrorCode:    "CANNOT_PROMOTE_TO_OWNER",
            ErrorMessage: "Promotion to owner role is not allowed",
            Duration:     int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("promotion to owner role is not allowed")
    }

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

    // CHECK IF TARGET IS ALREADY OWNER
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
                Message:     "Cannot modify owner admin",
            },
            AdminID:   promotedBy.String(),
            Action:    "promote_admin",
            Status:    "failed",
            ErrorCode: "CANNOT_MODIFY_OWNER",
            Duration:  int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("cannot modify owner admin")
    }

    if !promoter.CanPromoteToRole(newRoleMask) {
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
            AdminID:   promotedBy.String(),
            Action:    "promote_admin",
            Status:    "failed",
            ErrorCode: "UNAUTHORIZED",
            Duration:  int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("unauthorized: cannot promote to this role")
    }

    // VALIDATE VALID ROLE MASK (NOT OWNER)
    if !isValidRoleMask(newRoleMask) {
        s.logAdminEvent(ctx, &models.AdminLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "admin",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "warning",
                Message:     "Invalid role mask provided",
            },
            AdminID:   promotedBy.String(),
            Action:    "promote_admin",
            Status:    "failed",
            ErrorCode: "INVALID_ROLE_MASK",
            Duration:  int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("invalid role mask")
    }

    oldRoleMask := admin.AdminRoleMask

    if err := s.adminRepo.UpdateAdminRoleMask(ctx, adminID, newRoleMask, promotedBy); err != nil {
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

    newPermissions := s.getPermissionsForRole(newRoleMask)
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
        AdminRole:    getRoleStringFromMask(newRoleMask),
        TargetUserID: adminID.String(),
        Action:       "promote_admin",
        ResourceType: "admin_user",
        ResourceID:   adminID.String(),
        Status:       "success",
        Changes: map[string]interface{}{
            "old_role_mask": oldRoleMask,
            "new_role_mask": newRoleMask,
        },
        Duration: int64(time.Since(startTime).Milliseconds()),
    })

    return nil
}

// Helper function to validate role masks (exclude owner)
func isValidRoleMask(roleMask uint64) bool {
    switch roleMask {
    case models.RoleMaskSuperEmployee, models.RoleMaskEmployee:
        return true
    default:
        return false
    }
 }
// // RemoveAdmin removes an admin (soft delete)
// func (s *AdminService) RemoveAdmin(ctx context.Context, adminID uuid.UUID, removedBy uuid.UUID) error {
// 	startTime := time.Now()

// 	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
// 	if err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Admin not found for removal",
// 			},
// 			AdminID:      removedBy.String(),
// 			Action:       "remove_admin",
// 			Status:       "failed",
// 			ErrorCode:    "ADMIN_NOT_FOUND",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("admin not found: %w", err)
// 	}

// 	remover, err := s.adminRepo.GetAdminByID(ctx, removedBy)
// 	if err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Remover not found",
// 			},
// 			AdminID:      removedBy.String(),
// 			Action:       "remove_admin",
// 			Status:       "failed",
// 			ErrorCode:    "REMOVER_NOT_FOUND",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("remover not found: %w", err)
// 	}

// 	if !remover.CanManageEmployee(admin.AdminRoleMask) {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "warning",
// 				Message:     "Unauthorized removal attempt",
// 			},
// 			AdminID:   removedBy.String(),
// 			Action:    "remove_admin",
// 			Status:    "failed",
// 			ErrorCode: "UNAUTHORIZED",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("unauthorized: cannot remove admin with this role")
// 	}

// 	if admin.IsOwner() {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "warning",
// 				Message:     "Cannot remove owner admin",
// 			},
// 			AdminID:   removedBy.String(),
// 			Action:    "remove_admin",
// 			Status:    "failed",
// 			ErrorCode: "CANNOT_REMOVE_OWNER",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("cannot remove owner admin")
// 	}

// 	if err := s.adminRepo.RemoveAdmin(ctx, adminID, removedBy); err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Failed to remove admin",
// 			},
// 			AdminID:      removedBy.String(),
// 			Action:       "remove_admin",
// 			Status:       "failed",
// 			ErrorCode:    "REMOVE_FAILED",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("failed to remove admin: %w", err)
// 	}

// 	s.logAdminEvent(ctx, &models.AdminLogEvent{
// 		LogEnvelope: models.LogEnvelope{
// 			EventID:     uuid.New().String(),
// 			EventType:   "admin",
// 			ServiceName: "auth-service",
// 			Timestamp:   time.Now(),
// 			Environment: "production",
// 			Version:     "v1.0.0",
// 			Level:       "info",
// 			Message:     "Admin removed successfully",
// 		},
// 		AdminID:      adminID.String(),
// 		AdminRole:    admin.GetRoleString(),
// 		TargetUserID: adminID.String(),
// 		Action:       "remove_admin",
// 		ResourceType: "admin_user",
// 		ResourceID:   adminID.String(),
// 		Status:       "success",
// 		Duration:     int64(time.Since(startTime).Milliseconds()),
// 	})

// 	return nil
// }


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

    // BLOCK REMOVAL OF OWNER
    if admin.IsOwner() {
        s.logAdminEvent(ctx, &models.AdminLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "admin",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "error",
                Message:     "Cannot remove owner admin",
            },
            AdminID:   removedBy.String(),
            Action:    "remove_admin",
            Status:    "failed",
            ErrorCode: "CANNOT_REMOVE_OWNER",
            Duration:  int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("cannot remove owner admin")
    }

    if !remover.CanManageEmployee(admin.AdminRoleMask) {
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
            AdminID:   removedBy.String(),
            Action:    "remove_admin",
            Status:    "failed",
            ErrorCode: "UNAUTHORIZED",
            Duration:  int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("unauthorized: cannot remove admin with this role")
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
        AdminRole:    admin.GetRoleString(),
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
// func (s *AdminService) DeactivateAdmin(ctx context.Context, adminID uuid.UUID, deactivatedBy uuid.UUID) error {
// 	startTime := time.Now()

// 	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
// 	if err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Admin not found for deactivation",
// 			},
// 			AdminID:      deactivatedBy.String(),
// 			Action:       "deactivate_admin",
// 			Status:       "failed",
// 			ErrorCode:    "ADMIN_NOT_FOUND",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("admin not found: %w", err)
// 	}

// 	if !admin.IsActive {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "warning",
// 				Message:     "Admin already inactive",
// 			},
// 			AdminID:   deactivatedBy.String(),
// 			Action:    "deactivate_admin",
// 			Status:    "failed",
// 			ErrorCode: "ALREADY_INACTIVE",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("admin is already inactive")
// 	}

// 	if admin.IsOwner() {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "warning",
// 				Message:     "Cannot deactivate owner admin",
// 			},
// 			AdminID:   deactivatedBy.String(),
// 			Action:    "deactivate_admin",
// 			Status:    "failed",
// 			ErrorCode: "CANNOT_DEACTIVATE_OWNER",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("cannot deactivate owner admin")
// 	}

// 	if err := s.adminRepo.DeactivateAdmin(ctx, adminID); err != nil {
// 		s.logAdminEvent(ctx, &models.AdminLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "admin",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Failed to deactivate admin",
// 			},
// 			AdminID:      deactivatedBy.String(),
// 			Action:       "deactivate_admin",
// 			Status:       "failed",
// 			ErrorCode:    "DEACTIVATE_FAILED",
// 			ErrorMessage: err.Error(),
// 			Duration:     int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("failed to deactivate admin: %w", err)
// 	}

// 	s.logAdminEvent(ctx, &models.AdminLogEvent{
// 		LogEnvelope: models.LogEnvelope{
// 			EventID:     uuid.New().String(),
// 			EventType:   "admin",
// 			ServiceName: "auth-service",
// 			Timestamp:   time.Now(),
// 			Environment: "production",
// 			Version:     "v1.0.0",
// 			Level:       "info",
// 			Message:     "Admin deactivated successfully",
// 		},
// 		AdminID:      adminID.String(),
// 		AdminRole:    admin.GetRoleString(),
// 		TargetUserID: adminID.String(),
// 		Action:       "deactivate_admin",
// 		ResourceType: "admin_user",
// 		ResourceID:   adminID.String(),
// 		Status:       "success",
// 		Duration:     int64(time.Since(startTime).Milliseconds()),
// 	})

// 	return nil
// }



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
            AdminID:   deactivatedBy.String(),
            Action:    "deactivate_admin",
            Status:    "failed",
            ErrorCode: "ALREADY_INACTIVE",
            Duration:  int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("admin is already inactive")
    }

    // BLOCK DEACTIVATION OF OWNER
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
            AdminID:   deactivatedBy.String(),
            Action:    "deactivate_admin",
            Status:    "failed",
            ErrorCode: "CANNOT_DEACTIVATE_OWNER",
            Duration:  int64(time.Since(startTime).Milliseconds()),
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
        AdminRole:    admin.GetRoleString(),
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
			AdminID:   activatedBy.String(),
			Action:    "activate_admin",
			Status:    "failed",
			ErrorCode: "ALREADY_ACTIVE",
			Duration:  int64(time.Since(startTime).Milliseconds()),
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
		AdminRole:    admin.GetRoleString(),
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

// GetAdminsByRole retrieves admins by role mask
func (s *AdminService) GetAdminsByRole(ctx context.Context, roleMask uint64) ([]*models.AdminUser, error) {
	return s.adminRepo.GetAdminsByRole(ctx, roleMask)
}

// UpdateAdminPermissions updates admin permissions
func (s *AdminService) UpdateAdminPermissions(ctx context.Context, adminID uuid.UUID, permissionMask []uint64, updatedBy uuid.UUID) error {
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

	if !updater.CanManageEmployee(admin.AdminRoleMask) {
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
			AdminID:   updatedBy.String(),
			Action:    "update_admin_permissions",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("unauthorized: cannot update permissions for this admin role")
	}

	oldPermissions := admin.AdminPermissionMask

	if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, permissionMask); err != nil {
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
		AdminRole:    admin.GetRoleString(),
		TargetUserID: adminID.String(),
		Action:       "update_admin_permissions",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"old_permission_mask": oldPermissions,
			"new_permission_mask": permissionMask,
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
		AdminID:  adminID.String(),
		Action:   "record_admin_login",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
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
				AdminID:  adminID.String(),
				Action:   "admin_lockout",
				Status:   "success",
				Duration: int64(time.Since(startTime).Milliseconds()),
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
		AdminID:  adminID.String(),
		Action:   "failed_login_attempt",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return shouldLockout, attempts, nil
}

// ===== HELPER METHODS =====

// // getDefaultDataAccessScope returns default data access scope for role
// func (s *AdminService) getDefaultDataAccessScope(roleMask uint64) []string {
// 	if (roleMask & models.RoleMaskOwner) != 0 || (roleMask & models.RoleMaskSuperEmployee) != 0 {
// 		return []string{models.DataAccessGlobal}
// 	}
// 	if (roleMask & models.RoleMaskEmployee) != 0 {
// 		return []string{models.DataAccessGlobal}
// 	}
// 	return []string{models.DataAccessGlobal}
// }

// // getOwnerPermissions returns all permissions for owner
// func (s *AdminService) getOwnerPermissions() []uint64 {
// 	// Start with empty permission mask (4 uint64s for 229 permissions)
// 	permissionMask := make([]uint64, 4)
	
// 	// Set all admin permission bits (209-228)
// 	for bitIndex := 209; bitIndex <= 228; bitIndex++ {
// 		permissionMask = models.SetPermission(permissionMask, bitIndex, true)
// 	}
	
// 	return permissionMask
// }

// getPermissionsForRole returns permissions based on role
func (s *AdminService) getPermissionsForRole(roleMask uint64) []uint64 {
	permissionMask := make([]uint64, 4)
	
	// Owner gets all admin permissions
	if (roleMask & models.RoleMaskOwner) != 0 {
		return s.getOwnerPermissions()
	}
	
	// Super employee gets most admin permissions
	if (roleMask & models.RoleMaskSuperEmployee) != 0 {
		// Set permissions for super employee
		superEmployeePermissions := []string{
			models.PermissionAdminUserView,
			models.PermissionAdminRoleView,
			models.PermissionAdminPermissionView,
			models.PermissionAdminDepartmentView,
			models.PermissionAdminCompanyView,
			models.PermissionAdminAuditLogsView,
		}
		
		for _, perm := range superEmployeePermissions {
			if bitIndex, exists := models.AdminPermissionBitIndices[perm]; exists {
				permissionMask = models.SetPermission(permissionMask, bitIndex, true)
			}
		}
	}
	
	// Employee gets limited admin permissions
	if (roleMask & models.RoleMaskEmployee) != 0 {
		// Set permissions for employee
		employeePermissions := []string{
			models.PermissionAdminUserView,
			models.PermissionAdminRoleView,
			models.PermissionAdminDepartmentView,
			models.PermissionAdminAuditLogsView,
		}
		
		for _, perm := range employeePermissions {
			if bitIndex, exists := models.AdminPermissionBitIndices[perm]; exists {
				permissionMask = models.SetPermission(permissionMask, bitIndex, true)
			}
		}
	}
	
	return permissionMask
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

// Helper function to get role string from mask
func getRoleStringFromMask(roleMask uint64) string {
	if (roleMask & models.RoleMaskOwner) != 0 {
		return "owner"
	}
	if (roleMask & models.RoleMaskSuperEmployee) != 0 {
		return "super_employee"
	}
	if (roleMask & models.RoleMaskEmployee) != 0 {
		return "employee"
	}
	return "unknown"
}

// Add these methods to your AdminService

// GrantPermissionToAdmin grants a specific permission to an admin
func (s *AdminService) GrantPermissionToAdmin(ctx context.Context, adminID uuid.UUID, permissionName string, grantedBy uuid.UUID) error {
	startTime := time.Now()

	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("admin not found: %w", err)
	}

	granter, err := s.adminRepo.GetAdminByID(ctx, grantedBy)
	if err != nil {
		return fmt.Errorf("granter not found: %w", err)
	}

	if !granter.CanManageEmployee(admin.AdminRoleMask) {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized permission grant attempt",
			},
			AdminID:   grantedBy.String(),
			TargetUserID: adminID.String(),
			Action:    "grant_permission",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("unauthorized: cannot grant permission to this admin")
	}

	// Get bit index for permission
	bitIndex, exists := models.AdminPermissionBitIndices[permissionName]
	if !exists {
		return fmt.Errorf("invalid permission: %s", permissionName)
	}

	// Create new permission mask with the permission granted
	newPermissionMask := models.SetPermission(admin.CopyPermissionMask(), bitIndex, true)

	if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, newPermissionMask); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to grant permission",
			},
			AdminID:      grantedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "grant_permission",
			Status:       "failed",
			ErrorCode:    "GRANT_PERMISSION_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to grant permission: %w", err)
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
			Message:     "Permission granted successfully",
		},
		AdminID:      grantedBy.String(),
		TargetUserID: adminID.String(),
		Action:       "grant_permission",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"permission": permissionName,
			"bit_index":  bitIndex,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// RevokePermissionFromAdmin revokes a specific permission from an admin
func (s *AdminService) RevokePermissionFromAdmin(ctx context.Context, adminID uuid.UUID, permissionName string, revokedBy uuid.UUID) error {
	startTime := time.Now()

	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("admin not found: %w", err)
	}

	revoker, err := s.adminRepo.GetAdminByID(ctx, revokedBy)
	if err != nil {
		return fmt.Errorf("revoker not found: %w", err)
	}

	if !revoker.CanManageEmployee(admin.AdminRoleMask) {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "warning",
				Message:     "Unauthorized permission revoke attempt",
			},
			AdminID:   revokedBy.String(),
			TargetUserID: adminID.String(),
			Action:    "revoke_permission",
			Status:    "failed",
			ErrorCode: "UNAUTHORIZED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("unauthorized: cannot revoke permission from this admin")
	}

	// Get bit index for permission
	bitIndex, exists := models.AdminPermissionBitIndices[permissionName]
	if !exists {
		return fmt.Errorf("invalid permission: %s", permissionName)
	}

	// Create new permission mask with the permission revoked
	newPermissionMask := models.SetPermission(admin.CopyPermissionMask(), bitIndex, false)

	if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, newPermissionMask); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to revoke permission",
			},
			AdminID:      revokedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "revoke_permission",
			Status:       "failed",
			ErrorCode:    "REVOKE_PERMISSION_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to revoke permission: %w", err)
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
			Message:     "Permission revoked successfully",
		},
		AdminID:      revokedBy.String(),
		TargetUserID: adminID.String(),
		Action:       "revoke_permission",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"permission": permissionName,
			"bit_index":  bitIndex,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// GetAdminPermissions returns the list of permissions for an admin
func (s *AdminService) GetAdminPermissions(ctx context.Context, adminID uuid.UUID) ([]string, error) {
	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("admin not found: %w", err)
	}

	return admin.GetPermissionNames(), nil
}

// GetAdminPermissionMask returns the raw permission mask for an admin
func (s *AdminService) GetAdminPermissionMask(ctx context.Context, adminID uuid.UUID) ([]uint64, error) {
	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("admin not found: %w", err)
	}

	return admin.AdminPermissionMask, nil
}

// CheckAdminPermission checks if an admin has a specific permission
func (s *AdminService) CheckAdminPermission(ctx context.Context, adminID uuid.UUID, permissionName string) (bool, error) {
	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return false, fmt.Errorf("admin not found: %w", err)
	}

	return admin.HasPermission(permissionName), nil
}

// BatchUpdatePermissions updates multiple permissions at once
func (s *AdminService) BatchUpdatePermissions(ctx context.Context, adminID uuid.UUID, permissionsToGrant []string, permissionsToRevoke []string, updatedBy uuid.UUID) error {
	startTime := time.Now()

	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf("admin not found: %w", err)
	}

	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("updater not found: %w", err)
	}

	if !updater.CanManageEmployee(admin.AdminRoleMask) {
		return fmt.Errorf("unauthorized: cannot update permissions for this admin")
	}

	// Start with current permission mask
	newPermissionMask := admin.CopyPermissionMask()

	// Grant permissions
	for _, perm := range permissionsToGrant {
		if bitIndex, exists := models.AdminPermissionBitIndices[perm]; exists {
			newPermissionMask = models.SetPermission(newPermissionMask, bitIndex, true)
		}
	}

	// Revoke permissions
	for _, perm := range permissionsToRevoke {
		if bitIndex, exists := models.AdminPermissionBitIndices[perm]; exists {
			newPermissionMask = models.SetPermission(newPermissionMask, bitIndex, false)
		}
	}

	if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, newPermissionMask); err != nil {
		s.logAdminEvent(ctx, &models.AdminLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "admin",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to batch update permissions",
			},
			AdminID:      updatedBy.String(),
			TargetUserID: adminID.String(),
			Action:       "batch_update_permissions",
			Status:       "failed",
			ErrorCode:    "BATCH_UPDATE_PERMISSIONS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to batch update permissions: %w", err)
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
			Message:     "Batch permissions updated successfully",
		},
		AdminID:      updatedBy.String(),
		TargetUserID: adminID.String(),
		Action:       "batch_update_permissions",
		ResourceType: "admin_user",
		ResourceID:   adminID.String(),
		Status:       "success",
		Changes: map[string]interface{}{
			"granted":  permissionsToGrant,
			"revoked":  permissionsToRevoke,
			"total":    len(permissionsToGrant) + len(permissionsToRevoke),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}


// // InviteAdminWithDepartments invites a new admin with specific departments and permissions
// func (s *AdminService) InviteAdminWithDepartments(
// 	ctx context.Context, 
// 	phone string, 
// 	roleMask uint64, 
// 	departmentNames []string, 
// 	permissionNames []string,
// 	requesterID uuid.UUID,
// ) (*models.AdminUser, error) {
// 	startTime := time.Now()

// 	// Validate requester
// 	requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
// 	if err != nil {
// 		return nil, fmt.Errorf("requester not found: %w", err)
// 	}

// 	if !requester.IsActive {
// 		return nil, fmt.Errorf("requester is not active")
// 	}

// 	// Check if requester can invite to this role
// 	if !requester.CanPromoteToRole(roleMask) {
// 		return nil, fmt.Errorf("unauthorized: cannot invite to this role level")
// 	}

// 	// Check phone availability
// 	phoneHash := s.GeneratePhoneHash(phone)
// 	existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
// 	if err == nil && existingAdmin != nil {
// 		return nil, fmt.Errorf("phone number is already an admin")
// 	}

// 	// Get system departments
// 	systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get system departments: %w", err)
// 	}

// 	// Calculate department bitmask
// 	deptBitmask := uint64(0)
// 	accessibleModules := make(map[string]bool)
	
// 	for _, deptName := range departmentNames {
// 		found := false
// 		for _, sysDept := range systemDepartments {
// 			if strings.EqualFold(sysDept.Name, deptName) {
// 				deptBitmask |= sysDept.Bitmask
// 				accessibleModules[sysDept.ModuleCode] = true
// 				found = true
// 				break
// 			}
// 		}
// 		if !found {
// 			s.logger.Warn("Department not found", util.String("department", deptName))
// 		}
// 	}

// 	// Check if requester has access to all requested departments
// 	if !requester.IsOwner() {
// 		for _, deptName := range departmentNames {
// 			for _, sysDept := range systemDepartments {
// 				if strings.EqualFold(sysDept.Name, deptName) {
// 					if !requester.HasDepartmentAccess(sysDept.Bitmask) {
// 						return nil, fmt.Errorf("requester does not have access to department: %s", deptName)
// 					}
// 					break
// 				}
// 			}
// 		}
// 	}

// 	// Get permissions for the accessible modules
// 	accessiblePermissions := make([]string, 0)
// 	modulesList := make([]string, 0, len(accessibleModules))
// 	for module := range accessibleModules {
// 		modulesList = append(modulesList, module)
// 	}

// 	// Get module permissions
// 	if len(modulesList) > 0 {
// 		modulePermissions, err := s.companyRepo.GetModulePermissions(ctx, modulesList, "", "")
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to get module permissions: %w", err)
// 		}
		
// 		for _, perm := range modulePermissions {
// 			accessiblePermissions = append(accessiblePermissions, perm.PermissionName)
// 		}
// 	}

// 	// Add admin permissions if requested and requester has them
// 	finalPermissions := make([]string, 0)
// 	for _, permName := range permissionNames {
// 		// Check if permission is admin permission
// 		if strings.HasPrefix(permName, "admin.") {
// 			// Check if requester has this admin permission
// 			if !requester.HasPermission(permName) {
// 				return nil, fmt.Errorf("requester does not have admin permission: %s", permName)
// 			}
// 			finalPermissions = append(finalPermissions, permName)
// 		} else {
// 			// Check if module permission is accessible
// 			for _, accessiblePerm := range accessiblePermissions {
// 				if permName == accessiblePerm {
// 					finalPermissions = append(finalPermissions, permName)
// 					break
// 				}
// 			}
// 		}
// 	}

// 	// Encrypt phone
// 	encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to encrypt phone: %w", err)
// 	}

// 	keyID, err := uuid.Parse(encryptedResult.KeyID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse key ID: %w", err)
// 	}

// 	// Build permission bitmask
// 	permissionBitmask := s.buildPermissionMask(finalPermissions)

// 	adminID := uuid.New()
// 	now := time.Now().UTC()
// 	admin := &models.AdminUser{
// 		AdminID:             adminID,
// 		PhoneHash:           phoneHash,
// 		PhoneEncrypted:      encryptedResult.EncryptedValue,
// 		PhoneKeyID:          keyID,
// 		PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
// 		AdminRoleMask:       roleMask,
// 		AdminPermissionMask: permissionBitmask,
// 		DepartmentBitmask:   deptBitmask,
// 		AdminCreatedAt:      now,
// 		AdminCreatedBy:      requesterID,
// 		AdminUpdatedAt:      now,
// 		IsActive:            true,
// 		DataAccessScope:     s.getDefaultDataAccessScope(roleMask),
// 		IPWhitelist:         []string{},
// 		FailedLoginAttempts: 0,
// 		LastLogin:           time.Time{},
// 	}

// 	if err := s.adminRepo.CreateAdmin(ctx, admin); err != nil {
// 		return nil, fmt.Errorf("failed to invite user as admin: %w", err)
// 	}

// 	s.logger.Info("Admin invited successfully with departments",
// 		util.String("admin_id", adminID.String()),
// 		util.Uint64("role_mask", roleMask),
// 		util.Uint64("department_bitmask", deptBitmask),
// 		util.Strings("departments", departmentNames),
// 		util.Int("permissions_count", len(finalPermissions)),
// 		util.Strings("modules", modulesList))

// 	return admin, nil
// }

// // UpdateAdminDepartments updates an admin's accessible departments
// func (s *AdminService) UpdateAdminDepartments(
// 	ctx context.Context,
// 	adminID uuid.UUID,
// 	departmentNames []string,
// 	updatedBy uuid.UUID,
// ) error {
// 	startTime := time.Now()

// 	// Get admin to update
// 	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
// 	if err != nil {
// 		return fmt.Errorf("admin not found: %w", err)
// 	}

// 	// Get updater
// 	updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
// 	if err != nil {
// 		return fmt.Errorf("updater not found: %w", err)
// 	}

// 	// Check permissions
// 	if !updater.IsOwner() && !(updater.IsSuperEmployee() && admin.IsEmployee()) {
// 		return fmt.Errorf("unauthorized: cannot update this admin's departments")
// 	}

// 	// Get system departments
// 	systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
// 	if err != nil {
// 		return fmt.Errorf("failed to get system departments: %w", err)
// 	}

// 	// Calculate new department bitmask
// 	newDeptBitmask := uint64(0)
// 	accessibleModules := make(map[string]bool)
	
// 	for _, deptName := range departmentNames {
// 		found := false
// 		for _, sysDept := range systemDepartments {
// 			if strings.EqualFold(sysDept.Name, deptName) {
// 				// Check if updater has access to this department
// 				if !updater.IsOwner() && !updater.HasDepartmentAccess(sysDept.Bitmask) {
// 					return fmt.Errorf("updater does not have access to department: %s", deptName)
// 				}
// 				newDeptBitmask |= sysDept.Bitmask
// 				accessibleModules[sysDept.ModuleCode] = true
// 				found = true
// 				break
// 			}
// 		}
// 		if !found {
// 			s.logger.Warn("Department not found", util.String("department", deptName))
// 		}
// 	}

// 	// Update department bitmask
// 	if err := s.adminRepo.UpdateAdminDepartmentBitmask(ctx, adminID, newDeptBitmask); err != nil {
// 		return fmt.Errorf("failed to update department bitmask: %w", err)
// 	}

// 	// Update permissions to match new departments
// 	modulesList := make([]string, 0, len(accessibleModules))
// 	for module := range accessibleModules {
// 		modulesList = append(modulesList, module)
// 	}

// 	// Get current admin permissions
// 	currentPermissions := admin.GetPermissionNames()
	
// 	// Filter out permissions from modules admin no longer has access to
// 	newPermissions := make([]string, 0)
// 	for _, permName := range currentPermissions {
// 		// Keep admin permissions
// 		if strings.HasPrefix(permName, "admin.") {
// 			// Check if updater has this admin permission to grant it
// 			if updater.HasPermission(permName) {
// 				newPermissions = append(newPermissions, permName)
// 			}
// 			continue
// 		}
		
// 		// Keep only permissions from accessible modules
// 		for module := range accessibleModules {
// 			if strings.HasPrefix(permName, module+".") {
// 				newPermissions = append(newPermissions, permName)
// 				break
// 			}
// 		}
// 	}

// 	// Build new permission mask
// 	newPermissionMask := s.buildPermissionMask(newPermissions)
	
// 	// Update permissions
// 	if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, newPermissionMask); err != nil {
// 		return fmt.Errorf("failed to update permissions: %w", err)
// 	}

// 	s.logger.Info("Admin departments updated successfully",
// 		util.String("admin_id", adminID.String()),
// 		util.Uint64("old_department_bitmask", admin.DepartmentBitmask),
// 		util.Uint64("new_department_bitmask", newDeptBitmask),
// 		util.Strings("new_departments", departmentNames),
// 		util.Int("new_permissions_count", len(newPermissions)))

// 	return nil
// }

// GetAdminWithDetails returns admin details including accessible departments and permissions
func (s *AdminService) GetAdminWithDetails(ctx context.Context, adminID uuid.UUID) (*models.AdminUser, []string, []string, error) {
	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("admin not found: %w", err)
	}

	accessibleDepartments := admin.GetAccessibleDepartments()
	permissionNames := admin.GetPermissionNames()

	return admin, accessibleDepartments, permissionNames, nil
}

// CheckAdminDepartmentAccess checks if admin has access to specific department
func (s *AdminService) CheckAdminDepartmentAccess(ctx context.Context, adminID uuid.UUID, departmentName string) (bool, error) {
	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
	if err != nil {
		return false, fmt.Errorf("admin not found: %w", err)
	}

	// Owner has access to all departments
	if admin.IsOwner() {
		return true, nil
	}

	// Get system departments to find bitmask for department name
	systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get system departments: %w", err)
	}

	for _, dept := range systemDepartments {
		if strings.EqualFold(dept.Name, departmentName) {
			return admin.HasDepartmentAccess(dept.Bitmask), nil
		}
	}

	return false, nil
}

// // Helper method to build permission mask from permission names
// func (s *AdminService) buildPermissionMask(permissionNames []string) []uint64 {
// 	permissionMask := make([]uint64, 4)
	
// 	for _, permName := range permissionNames {
// 		if bitIndex, exists := models.AdminPermissionBitIndices[permName]; exists {
// 			permissionMask = models.SetPermission(permissionMask, bitIndex, true)
// 		}
// 	}
	
// 	return permissionMask
// }

// Get owner permissions (all permissions)
func (s *AdminService) getOwnerPermissions() []uint64 {
	permissionMask := make([]uint64, 4)
	
	// Set all bits (0-228)
	for i := 0; i <= 228; i++ {
		permissionMask = models.SetPermission(permissionMask, i, true)
	}
	
	return permissionMask
}

// Get default data access scope based on role
func (s *AdminService) getDefaultDataAccessScope(roleMask uint64) []string {
	if (roleMask & models.RoleMaskOwner) != 0 {
		return []string{models.DataAccessGlobal}
	}
	return []string{models.DataAccessGlobal}
}

// Generate phone hash
func (s *AdminService) GeneratePhoneHash(phoneNumber string) string {
	normalized := strings.ReplaceAll(phoneNumber, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "(", "")
	normalized = strings.ReplaceAll(normalized, ")", "")

	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

func (s *AdminService) InitializeOwner(ctx context.Context, phone string) (*models.AdminUser, error) {
    startTime := time.Now() // ✅ Keep this declaration

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
            Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
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
            Duration:  int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
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
            Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
        })
        return nil, fmt.Errorf("failed to encrypt phone: %w", err)
    }

    keyID, err := uuid.Parse(encryptedResult.KeyID)
    if err != nil {
        return nil, fmt.Errorf("failed to parse key ID: %w", err)
    }

    // Get all system departments to calculate full bitmask
    systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
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
                Message:     "Failed to get system departments",
            },
            Action:       "initialize_owner",
            Status:       "failed",
            ErrorCode:    "GET_SYSTEM_DEPTS_FAILED",
            ErrorMessage: err.Error(),
            Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
        })
        return nil, fmt.Errorf("failed to get system departments: %w", err)
    }

    // Calculate full department bitmask (all 16 departments)
    fullDeptBitmask := uint64(0)
    for _, dept := range systemDepartments {
        if dept.Bitmask > 0 {
            fullDeptBitmask |= dept.Bitmask
        }
    }

    ownerID := uuid.New()
    owner := &models.AdminUser{
        AdminID:             ownerID,
        PhoneHash:           phoneHash,
        PhoneEncrypted:      encryptedResult.EncryptedValue,
        PhoneKeyID:          keyID,
        PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
        AdminRoleMask:       models.RoleMaskOwner,
        AdminPermissionMask: s.getOwnerPermissions(),
        DepartmentBitmask:   fullDeptBitmask, // Owner gets all departments
        AdminCreatedAt:      time.Now().UTC(),
        AdminCreatedBy:      ownerID,
        AdminUpdatedAt:      time.Now().UTC(),
        IsActive:            true,
        DataAccessScope:     []string{models.DataAccessGlobal},
        IPWhitelist:         []string{},
        FailedLoginAttempts: 0,
        LastLogin:           time.Time{},
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
            Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
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
        AdminRole: "owner",
        Action:    "initialize_owner",
        Status:    "success",
        Duration:  int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
    })

    s.logger.Info("Owner initialized successfully",
        util.String("admin_id", owner.AdminID.String()),
        util.Uint64("department_bitmask", owner.DepartmentBitmask),
        util.Strings("accessible_departments", owner.GetAccessibleDepartments()))

    return owner, nil
}
func (s *AdminService) ChangeAdminPhone(ctx context.Context, targetAdminID uuid.UUID, newPhone string, requesterID uuid.UUID) error {
    startTime := time.Now() // ✅ Keep this declaration

    if targetAdminID == uuid.Nil {
        return fmt.Errorf("invalid target admin ID")
    }
    if newPhone == "" {
        return fmt.Errorf("new phone cannot be empty")
    }
    if requesterID == uuid.Nil {
        return fmt.Errorf("invalid requester ID")
    }

    // Get requester admin
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
            AdminID:   requesterID.String(),
            TargetUserID: targetAdminID.String(),
            Action:    "change_admin_phone",
            Status:    "failed",
            ErrorCode: "REQUESTER_NOT_FOUND",
            ErrorMessage: err.Error(),
            Duration:  int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
        })
        return fmt.Errorf("requester not found: %w", err)
    }

    // Get target admin
    targetAdmin, err := s.adminRepo.GetAdminByID(ctx, targetAdminID)
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
                Message:     "Target admin not found",
            },
            AdminID:   requesterID.String(),
            TargetUserID: targetAdminID.String(),
            Action:    "change_admin_phone",
            Status:    "failed",
            ErrorCode: "TARGET_ADMIN_NOT_FOUND",
            ErrorMessage: err.Error(),
            Duration:  int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
        })
        return fmt.Errorf("target admin not found: %w", err)
    }

    // Check hierarchy rules
    if !s.canChangePhone(requester, targetAdmin) {
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
            AdminID:   requesterID.String(),
            TargetUserID: targetAdminID.String(),
            Action:    "change_admin_phone",
            Status:    "failed",
            ErrorCode: "UNAUTHORIZED",
            Duration:  int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
        })
        return fmt.Errorf("unauthorized: cannot change phone for this admin")
    }

    newPhoneHash := s.GeneratePhoneHash(newPhone)

    // Check if new phone is already used by another admin
    existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, newPhoneHash)
    if err == nil && existingAdmin != nil && existingAdmin.AdminID != targetAdminID {
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
            AdminID:   requesterID.String(),
            TargetUserID: targetAdminID.String(),
            Action:    "change_admin_phone",
            Status:    "failed",
            ErrorCode: "PHONE_ALREADY_USED",
            Duration:  int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
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
            AdminID:      requesterID.String(),
            TargetUserID: targetAdminID.String(),
            Action:       "change_admin_phone",
            Status:       "failed",
            ErrorCode:    "PHONE_ENCRYPTION_FAILED",
            ErrorMessage: err.Error(),
            Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
        })
        return fmt.Errorf("failed to encrypt new phone: %w", err)
    }

    keyID, err := uuid.Parse(encryptedResult.KeyID)
    if err != nil {
        return fmt.Errorf("failed to parse key ID: %w", err)
    }

    if err := s.adminRepo.UpdateAdminPhone(ctx, targetAdminID, newPhoneHash, encryptedResult.EncryptedValue, keyID, encryptedResult.EncryptedDEK); err != nil {
        s.logAdminEvent(ctx, &models.AdminLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "admin",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "error",
                Message:     "Failed to update admin phone in database",
            },
            AdminID:      requesterID.String(),
            TargetUserID: targetAdminID.String(),
            Action:       "change_admin_phone",
            Status:       "failed",
            ErrorCode:    "UPDATE_PHONE_FAILED",
            ErrorMessage: err.Error(),
            Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
        })
        return fmt.Errorf("failed to update admin phone: %w", err)
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
            Message:     "Admin phone updated successfully",
        },
        AdminID:   requesterID.String(),
        TargetUserID: targetAdminID.String(),
        AdminRole: requester.GetRoleString(),
        Action:    "change_admin_phone",
        Status:    "success",
        Duration:  int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
    })

    return nil
}

// func (s *AdminService) UpdateAdminDepartments(
//     ctx context.Context,
//     adminID uuid.UUID,
//     departmentNames []string,
//     updatedBy uuid.UUID,
// ) error {
//     startTime := time.Now() // ✅ Keep this declaration

//     // Get admin to update
//     admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Admin not found for department update",
//             },
//             AdminID:      updatedBy.String(),
//             TargetUserID: adminID.String(),
//             Action:       "update_admin_departments",
//             Status:       "failed",
//             ErrorCode:    "ADMIN_NOT_FOUND",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
//         })
//         return fmt.Errorf("admin not found: %w", err)
//     }

//     // Get updater
//     updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Updater not found",
//             },
//             AdminID:      updatedBy.String(),
//             TargetUserID: adminID.String(),
//             Action:       "update_admin_departments",
//             Status:       "failed",
//             ErrorCode:    "UPDATER_NOT_FOUND",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
//         })
//         return fmt.Errorf("updater not found: %w", err)
//     }

//     // Check permissions
//     if !updater.IsOwner() && !(updater.IsSuperEmployee() && admin.IsEmployee()) {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "warning",
//                 Message:     "Unauthorized department update attempt",
//             },
//             AdminID:      updatedBy.String(),
//             TargetUserID: adminID.String(),
//             Action:       "update_admin_departments",
//             Status:       "failed",
//             ErrorCode:    "UNAUTHORIZED",
//             Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
//         })
//         return fmt.Errorf("unauthorized: cannot update this admin's departments")
//     }

//     // Get system departments
//     systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to get system departments",
//             },
//             AdminID:      updatedBy.String(),
//             TargetUserID: adminID.String(),
//             Action:       "update_admin_departments",
//             Status:       "failed",
//             ErrorCode:    "GET_SYSTEM_DEPTS_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
//         })
//         return fmt.Errorf("failed to get system departments: %w", err)
//     }

//     // Calculate new department bitmask
//     newDeptBitmask := uint64(0)
//     accessibleModules := make(map[string]bool)
    
//     for _, deptName := range departmentNames {
//         found := false
//         for _, sysDept := range systemDepartments {
//             if strings.EqualFold(sysDept.Name, deptName) {
//                 // Check if updater has access to this department
//                 if !updater.IsOwner() && !updater.HasDepartmentAccess(sysDept.Bitmask) {
//                     s.logAdminEvent(ctx, &models.AdminLogEvent{
//                         LogEnvelope: models.LogEnvelope{
//                             EventID:     uuid.New().String(),
//                             EventType:   "admin",
//                             ServiceName: "auth-service",
//                             Timestamp:   time.Now(),
//                             Environment: "production",
//                             Version:     "v1.0.0",
//                             Level:       "warning",
//                             Message:     "Updater lacks department access",
//                         },
//                         AdminID:      updatedBy.String(),
//                         TargetUserID: adminID.String(),
//                         Action:       "update_admin_departments",
//                         Status:       "failed",
//                         ErrorCode:    "NO_DEPARTMENT_ACCESS",
//                         Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
//                     })
//                     return fmt.Errorf("updater does not have access to department: %s", deptName)
//                 }
//                 newDeptBitmask |= sysDept.Bitmask
//                 accessibleModules[sysDept.ModuleCode] = true
//                 found = true
//                 break
//             }
//         }
//         if !found {
//             s.logger.Warn("Department not found", util.String("department", deptName))
//         }
//     }

//     // Update department bitmask
//     if err := s.adminRepo.UpdateAdminDepartmentBitmask(ctx, adminID, newDeptBitmask); err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to update department bitmask",
//             },
//             AdminID:      updatedBy.String(),
//             TargetUserID: adminID.String(),
//             Action:       "update_admin_departments",
//             Status:       "failed",
//             ErrorCode:    "UPDATE_DEPARTMENT_BITMASK_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
//         })
//         return fmt.Errorf("failed to update department bitmask: %w", err)
//     }

//     // Update permissions to match new departments
//     modulesList := make([]string, 0, len(accessibleModules))
//     for module := range accessibleModules {
//         modulesList = append(modulesList, module)
//     }

//     // Get current admin permissions
//     currentPermissions := admin.GetPermissionNames()
    
//     // Filter out permissions from modules admin no longer has access to
//     newPermissions := make([]string, 0)
//     for _, permName := range currentPermissions {
//         // Keep admin permissions
//         if strings.HasPrefix(permName, "admin.") {
//             // Check if updater has this admin permission to grant it
//             if updater.HasPermission(permName) {
//                 newPermissions = append(newPermissions, permName)
//             }
//             continue
//         }
        
//         // Keep only permissions from accessible modules
//         for module := range accessibleModules {
//             if strings.HasPrefix(permName, module+".") {
//                 newPermissions = append(newPermissions, permName)
//                 break
//             }
//         }
//     }

//     // Build new permission mask
//     newPermissionMask := s.buildPermissionMask(newPermissions)
    
//     // Update permissions
//     if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, newPermissionMask); err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to update permissions",
//             },
//             AdminID:      updatedBy.String(),
//             TargetUserID: adminID.String(),
//             Action:       "update_admin_departments",
//             Status:       "failed",
//             ErrorCode:    "UPDATE_PERMISSIONS_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
//         })
//         return fmt.Errorf("failed to update permissions: %w", err)
//     }

//     s.logAdminEvent(ctx, &models.AdminLogEvent{
//         LogEnvelope: models.LogEnvelope{
//             EventID:     uuid.New().String(),
//             EventType:   "admin",
//             ServiceName: "auth-service",
//             Timestamp:   time.Now(),
//             Environment: "production",
//             Version:     "v1.0.0",
//             Level:       "info",
//             Message:     "Admin departments updated successfully",
//         },
//         AdminID:      updatedBy.String(),
//         TargetUserID: adminID.String(),
//         Action:       "update_admin_departments",
//         ResourceType: "admin_user",
//         ResourceID:   adminID.String(),
//         Status:       "success",
//         Changes: map[string]interface{}{
//             "old_department_bitmask": admin.DepartmentBitmask,
//             "new_department_bitmask": newDeptBitmask,
//             "new_departments":        departmentNames,
//             "new_permissions_count":  len(newPermissions),
//         },
//         Duration: int64(time.Since(startTime).Milliseconds()), // ✅ Add duration here
//     })

//     s.logger.Info("Admin departments updated successfully",
//         util.String("admin_id", adminID.String()),
//         util.Uint64("old_department_bitmask", admin.DepartmentBitmask),
//         util.Uint64("new_department_bitmask", newDeptBitmask),
//         util.Strings("new_departments", departmentNames),
//         util.Int("new_permissions_count", len(newPermissions)))

//     return nil
// }



// // InviteAdminWithDepartments invites a new admin with specific departments and permissions
// func (s *AdminService) InviteAdminWithDepartments(
//     ctx context.Context, 
//     phone string, 
//     roleMask uint64, 
//     departmentNames []string, 
//     permissionNames []string,
//     requesterID uuid.UUID,
// ) (*models.AdminUser, error) {
//     startTime := time.Now()

//     // Validate requester
//     requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Requester not found for admin invitation",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "REQUESTER_NOT_FOUND",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("requester not found: %w", err)
//     }

//     if !requester.IsActive {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "warning",
//                 Message:     "Requester is not active",
//             },
//             AdminID:   requesterID.String(),
//             Action:    "invite_admin_with_departments",
//             Status:    "failed",
//             ErrorCode: "REQUESTER_INACTIVE",
//             Duration:  int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("requester is not active")
//     }

//     // Check if requester can invite to this role
//     if !requester.CanPromoteToRole(roleMask) {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "warning",
//                 Message:     "Unauthorized role invitation attempt",
//             },
//             AdminID:   requesterID.String(),
//             Action:    "invite_admin_with_departments",
//             Status:    "failed",
//             ErrorCode: "UNAUTHORIZED_ROLE",
//             Duration:  int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("unauthorized: cannot invite to this role level")
//     }

//     // Check phone availability
//     phoneHash := s.GeneratePhoneHash(phone)
//     existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
//     if err == nil && existingAdmin != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "warning",
//                 Message:     "Phone already used by another admin",
//             },
//             AdminID:   requesterID.String(),
//             Action:    "invite_admin_with_departments",
//             Status:    "failed",
//             ErrorCode: "PHONE_ALREADY_ADMIN",
//             Duration:  int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("phone number is already an admin")
//     }

//     // Get system departments
//     systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to get system departments",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "GET_SYSTEM_DEPTS_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("failed to get system departments: %w", err)
//     }

//     // Calculate department bitmask
//     deptBitmask := uint64(0)
//     accessibleModules := make(map[string]bool)
    
//     for _, deptName := range departmentNames {
//         found := false
//         for _, sysDept := range systemDepartments {
//             if strings.EqualFold(sysDept.Name, deptName) {
//                 deptBitmask |= sysDept.Bitmask
//                 accessibleModules[sysDept.ModuleCode] = true
//                 found = true
//                 break
//             }
//         }
//         if !found {
//             s.logger.Warn("Department not found", util.String("department", deptName))
//         }
//     }

//     // Check if requester has access to all requested departments
//     if !requester.IsOwner() {
//         for _, deptName := range departmentNames {
//             for _, sysDept := range systemDepartments {
//                 if strings.EqualFold(sysDept.Name, deptName) {
//                     if !requester.HasDepartmentAccess(sysDept.Bitmask) {
//                         s.logAdminEvent(ctx, &models.AdminLogEvent{
//                             LogEnvelope: models.LogEnvelope{
//                                 EventID:     uuid.New().String(),
//                                 EventType:   "admin",
//                                 ServiceName: "auth-service",
//                                 Timestamp:   time.Now(),
//                                 Environment: "production",
//                                 Version:     "v1.0.0",
//                                 Level:       "warning",
//                                 Message:     "Requester lacks department access",
//                             },
//                             AdminID:   requesterID.String(),
//                             Action:    "invite_admin_with_departments",
//                             Status:    "failed",
//                             ErrorCode: "NO_DEPARTMENT_ACCESS",
//                             Changes: map[string]interface{}{
//                                 "department": deptName,
//                                 "bitmask":    sysDept.Bitmask,
//                             },
//                             Duration: int64(time.Since(startTime).Milliseconds()),
//                         })
//                         return nil, fmt.Errorf("requester does not have access to department: %s", deptName)
//                     }
//                     break
//                 }
//             }
//         }
//     }

//     // Get permissions for the accessible modules
//     accessiblePermissions := make([]string, 0)
//     modulesList := make([]string, 0, len(accessibleModules))
//     for module := range accessibleModules {
//         modulesList = append(modulesList, module)
//     }

//     // Get module permissions
//     if len(modulesList) > 0 {
//         modulePermissions, err := s.companyRepo.GetModulePermissions(ctx, modulesList, "", "")
//         if err != nil {
//             s.logAdminEvent(ctx, &models.AdminLogEvent{
//                 LogEnvelope: models.LogEnvelope{
//                     EventID:     uuid.New().String(),
//                     EventType:   "admin",
//                     ServiceName: "auth-service",
//                     Timestamp:   time.Now(),
//                     Environment: "production",
//                     Version:     "v1.0.0",
//                     Level:       "error",
//                     Message:     "Failed to get module permissions",
//                 },
//                 AdminID:      requesterID.String(),
//                 Action:       "invite_admin_with_departments",
//                 Status:       "failed",
//                 ErrorCode:    "GET_MODULE_PERMISSIONS_FAILED",
//                 ErrorMessage: err.Error(),
//                 Duration:     int64(time.Since(startTime).Milliseconds()),
//             })
//             return nil, fmt.Errorf("failed to get module permissions: %w", err)
//         }
        
//         for _, perm := range modulePermissions {
//             accessiblePermissions = append(accessiblePermissions, perm.PermissionName)
//         }
//     }

//     // Add admin permissions if requested and requester has them
//     finalPermissions := make([]string, 0)
//     for _, permName := range permissionNames {
//         // Check if permission is admin permission
//         if strings.HasPrefix(permName, "admin.") {
//             // Check if requester has this admin permission
//             if !requester.HasPermission(permName) {
//                 s.logAdminEvent(ctx, &models.AdminLogEvent{
//                     LogEnvelope: models.LogEnvelope{
//                         EventID:     uuid.New().String(),
//                         EventType:   "admin",
//                         ServiceName: "auth-service",
//                         Timestamp:   time.Now(),
//                         Environment: "production",
//                         Version:     "v1.0.0",
//                         Level:       "warning",
//                         Message:     "Requester lacks admin permission",
//                     },
//                     AdminID:   requesterID.String(),
//                     Action:    "invite_admin_with_departments",
//                     Status:    "failed",
//                     ErrorCode: "NO_ADMIN_PERMISSION",
//                     Changes: map[string]interface{}{
//                         "permission": permName,
//                     },
//                     Duration: int64(time.Since(startTime).Milliseconds()),
//                 })
//                 return nil, fmt.Errorf("requester does not have admin permission: %s", permName)
//             }
//             finalPermissions = append(finalPermissions, permName)
//         } else {
//             // Check if module permission is accessible
//             found := false
//             for _, accessiblePerm := range accessiblePermissions {
//                 if permName == accessiblePerm {
//                     finalPermissions = append(finalPermissions, permName)
//                     found = true
//                     break
//                 }
//             }
//             if !found {
//                 s.logger.Warn("Permission not accessible for invited admin",
//                     util.String("permission", permName),
//                     util.String("requester_id", requesterID.String()))
//             }
//         }
//     }

//     // Encrypt phone
//     encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to encrypt phone for admin invitation",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "PHONE_ENCRYPTION_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("failed to encrypt phone: %w", err)
//     }

//     keyID, err := uuid.Parse(encryptedResult.KeyID)
//     if err != nil {
//         return nil, fmt.Errorf("failed to parse key ID: %w", err)
//     }

//     // Build permission bitmask
//     permissionBitmask := s.buildPermissionMask(finalPermissions)

//     adminID := uuid.New()
//     now := time.Now().UTC()
//     admin := &models.AdminUser{
//         AdminID:             adminID,
//         PhoneHash:           phoneHash,
//         PhoneEncrypted:      encryptedResult.EncryptedValue,
//         PhoneKeyID:          keyID,
//         PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
//         AdminRoleMask:       roleMask,
//         AdminPermissionMask: permissionBitmask,
//         DepartmentBitmask:   deptBitmask,
//         AdminCreatedAt:      now,
//         AdminCreatedBy:      requesterID,
//         AdminUpdatedAt:      now,
//         IsActive:            true,
//         DataAccessScope:     s.getDefaultDataAccessScope(roleMask),
//         IPWhitelist:         []string{},
//         FailedLoginAttempts: 0,
//         LastLogin:           time.Time{},
//     }

//     if err := s.adminRepo.CreateAdmin(ctx, admin); err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to create admin in database",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "CREATE_ADMIN_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("failed to invite user as admin: %w", err)
//     }

//     // Log success
//     s.logAdminEvent(ctx, &models.AdminLogEvent{
//         LogEnvelope: models.LogEnvelope{
//             EventID:     uuid.New().String(),
//             EventType:   "admin",
//             ServiceName: "auth-service",
//             Timestamp:   time.Now(),
//             Environment: "production",
//             Version:     "v1.0.0",
//             Level:       "info",
//             Message:     "Admin invited successfully with departments",
//         },
//         AdminID:      requesterID.String(),
//         TargetUserID: adminID.String(),
//         AdminRole:    requester.GetRoleString(),
//         Action:       "invite_admin_with_departments",
//         ResourceType: "admin_user",
//         ResourceID:   adminID.String(),
//         Status:       "success",
//         Changes: map[string]interface{}{
//             "role_mask":          roleMask,
//             "department_bitmask": deptBitmask,
//             "departments":        departmentNames,
//             "permissions_count":  len(finalPermissions),
//             "modules":            modulesList,
//         },
//         Duration: int64(time.Since(startTime).Milliseconds()),
//     })

//     s.logger.Info("Admin invited successfully with departments",
//         util.String("admin_id", adminID.String()),
//         util.Uint64("role_mask", roleMask),
//         util.Uint64("department_bitmask", deptBitmask),
//         util.Strings("departments", departmentNames),
//         util.Int("permissions_count", len(finalPermissions)),
//         util.Strings("modules", modulesList))

//     return admin, nil
// }
// func (s *AdminService) InviteAdminWithDepartments(
//     ctx context.Context,
//     phone string,
//     roleMask uint64,
//     departmentNames []string,
//     permissionNames []string,
//     requesterID uuid.UUID,
// ) (*models.AdminUser, error) {
//     startTime := time.Now()

//     requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Requester not found for admin invitation",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "REQUESTER_NOT_FOUND",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("requester not found: %w", err)
//     }

//     if !requester.IsActive {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "warning",
//                 Message:     "Requester is not active",
//             },
//             AdminID:   requesterID.String(),
//             Action:    "invite_admin_with_departments",
//             Status:    "failed",
//             ErrorCode: "REQUESTER_INACTIVE",
//             Duration:  int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("requester is not active")
//     }

//     if !requester.CanPromoteToRole(roleMask) {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "warning",
//                 Message:     "Unauthorized role invitation attempt",
//             },
//             AdminID:   requesterID.String(),
//             Action:    "invite_admin_with_departments",
//             Status:    "failed",
//             ErrorCode: "UNAUTHORIZED_ROLE",
//             Duration:  int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("unauthorized: cannot invite to this role level")
//     }

//     phoneHash := s.GeneratePhoneHash(phone)
//     existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
//     if err == nil && existingAdmin != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "warning",
//                 Message:     "Phone already used by another admin",
//             },
//             AdminID:   requesterID.String(),
//             Action:    "invite_admin_with_departments",
//             Status:    "failed",
//             ErrorCode: "PHONE_ALREADY_ADMIN",
//             Duration:  int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("phone number is already an admin")
//     }

//     systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to get system departments",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "GET_SYSTEM_DEPTS_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("failed to get system departments: %w", err)
//     }

//     deptBitmask := uint64(0)
//     accessibleModules := make(map[string]bool)

//     for _, deptName := range departmentNames {
//         found := false
//         for _, sysDept := range systemDepartments {
//             if strings.EqualFold(sysDept.Name, deptName) {
//                 deptBitmask |= sysDept.Bitmask
//                 accessibleModules[sysDept.ModuleCode] = true
//                 found = true
//                 break
//             }
//         }
//         if !found {
//             s.logger.Warn("Department not found", util.String("department", deptName))
//         }
//     }

//     if !requester.IsOwner() {
//         for _, deptName := range departmentNames {
//             for _, sysDept := range systemDepartments {
//                 if strings.EqualFold(sysDept.Name, deptName) {
//                     if !requester.HasDepartmentAccess(sysDept.Bitmask) {
//                         s.logAdminEvent(ctx, &models.AdminLogEvent{
//                             LogEnvelope: models.LogEnvelope{
//                                 EventID:     uuid.New().String(),
//                                 EventType:   "admin",
//                                 ServiceName: "auth-service",
//                                 Timestamp:   time.Now(),
//                                 Environment: "production",
//                                 Version:     "v1.0.0",
//                                 Level:       "warning",
//                                 Message:     "Requester lacks department access",
//                             },
//                             AdminID:   requesterID.String(),
//                             Action:    "invite_admin_with_departments",
//                             Status:    "failed",
//                             ErrorCode: "NO_DEPARTMENT_ACCESS",
//                             Changes: map[string]interface{}{
//                                 "department": deptName,
//                                 "bitmask":    sysDept.Bitmask,
//                             },
//                             Duration: int64(time.Since(startTime).Milliseconds()),
//                         })
//                         return nil, fmt.Errorf("requester does not have access to department: %s", deptName)
//                     }
//                     break
//                 }
//             }
//         }
//     }

//     // Get permissions for the modules
//     accessiblePermissions := make([]string, 0)
//     modulesList := make([]string, 0, len(accessibleModules))
//     for module := range accessibleModules {
//         modulesList = append(modulesList, module)
//     }

//     if len(modulesList) > 0 {
//         // Get all permissions first
//         allPermissions, err := s.companyRepo.GetAllPermissions(ctx)
//         if err != nil {
//             s.logAdminEvent(ctx, &models.AdminLogEvent{
//                 LogEnvelope: models.LogEnvelope{
//                     EventID:     uuid.New().String(),
//                     EventType:   "admin",
//                     ServiceName: "auth-service",
//                     Timestamp:   time.Now(),
//                     Environment: "production",
//                     Version:     "v1.0.0",
//                     Level:       "error",
//                     Message:     "Failed to get all permissions",
//                 },
//                 AdminID:      requesterID.String(),
//                 Action:       "invite_admin_with_departments",
//                 Status:       "failed",
//                 ErrorCode:    "GET_ALL_PERMISSIONS_FAILED",
//                 ErrorMessage: err.Error(),
//                 Duration:     int64(time.Since(startTime).Milliseconds()),
//             })
//             return nil, fmt.Errorf("failed to get all permissions: %w", err)
//         }

//         // Filter permissions by modules
//         for _, perm := range allPermissions {
//             for _, module := range modulesList {
//                 if perm.Module == module {
//                     accessiblePermissions = append(accessiblePermissions, perm.PermissionName)
//                     break
//                 }
//             }
//         }

//         s.logger.Info("Module permissions retrieved",
//             util.Strings("modules", modulesList),
//             util.Int("total_permissions", len(accessiblePermissions)))
//     }

//     // Combine accessible permissions with requested permissions
//     finalPermissions := make([]string, 0)
    
//     // Start with accessible permissions from departments
//     finalPermissions = append(finalPermissions, accessiblePermissions...)
    
//     // Add requested permissions
//     for _, permName := range permissionNames {
//         // Check if it's an admin permission
//         if strings.HasPrefix(permName, "admin.") {
//             // Verify requester has this admin permission
//             if !requester.HasPermission(permName) {
//                 s.logAdminEvent(ctx, &models.AdminLogEvent{
//                     LogEnvelope: models.LogEnvelope{
//                         EventID:     uuid.New().String(),
//                         EventType:   "admin",
//                         ServiceName: "auth-service",
//                         Timestamp:   time.Now(),
//                         Environment: "production",
//                         Version:     "v1.0.0",
//                         Level:       "warning",
//                         Message:     "Requester lacks admin permission",
//                     },
//                     AdminID:   requesterID.String(),
//                     Action:    "invite_admin_with_departments",
//                     Status:    "failed",
//                     ErrorCode: "NO_ADMIN_PERMISSION",
//                     Changes: map[string]interface{}{
//                         "permission": permName,
//                     },
//                     Duration: int64(time.Since(startTime).Milliseconds()),
//                 })
//                 return nil, fmt.Errorf("requester does not have admin permission: %s", permName)
//             }
//         }
        
//         // Check if already in finalPermissions
//         alreadyExists := false
//         for _, p := range finalPermissions {
//             if p == permName {
//                 alreadyExists = true
//                 break
//             }
//         }
        
//         if !alreadyExists {
//             // For non-admin permissions, verify they exist in accessiblePermissions
//             if !strings.HasPrefix(permName, "admin.") {
//                 permExists := false
//                 for _, accessiblePerm := range accessiblePermissions {
//                     if permName == accessiblePerm {
//                         permExists = true
//                         break
//                     }
//                 }
//                 if !permExists {
//                     s.logger.Warn("Permission may not exist in accessible modules",
//                         util.String("permission", permName),
//                         util.String("requester_id", requesterID.String()))
//                 }
//             }
//             finalPermissions = append(finalPermissions, permName)
//         }
//     }

//     encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to encrypt phone for admin invitation",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "PHONE_ENCRYPTION_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("failed to encrypt phone: %w", err)
//     }

//     keyID, err := uuid.Parse(encryptedResult.KeyID)
//     if err != nil {
//         return nil, fmt.Errorf("failed to parse key ID: %w", err)
//     }

//     permissionBitmask, err := s.buildPermissionMask(ctx, finalPermissions)

//     adminID := uuid.New()
//     now := time.Now().UTC()
//     admin := &models.AdminUser{
//         AdminID:             adminID,
//         PhoneHash:           phoneHash,
//         PhoneEncrypted:      encryptedResult.EncryptedValue,
//         PhoneKeyID:          keyID,
//         PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
//         AdminRoleMask:       roleMask,
//         AdminPermissionMask: permissionBitmask,
//         DepartmentBitmask:   deptBitmask,
//         AdminCreatedAt:      now,
//         AdminCreatedBy:      requesterID,
//         AdminUpdatedAt:      now,
//         IsActive:            true,
//         DataAccessScope:     s.getDefaultDataAccessScope(roleMask),
//         IPWhitelist:         []string{},
//         FailedLoginAttempts: 0,
//         LastLogin:           time.Time{},
//     }

//     if err := s.adminRepo.CreateAdmin(ctx, admin); err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to create admin in database",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "CREATE_ADMIN_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("failed to invite user as admin: %w", err)
//     }

//     // Log detailed information for debugging
//     s.logger.Info("Admin invited successfully with departments and permissions",
//         util.String("admin_id", adminID.String()),
//         util.Uint64("role_mask", roleMask),
//         util.Uint64("department_bitmask", deptBitmask),
//         util.Strings("departments", departmentNames),
//         util.Strings("accessible_modules", modulesList),
//         util.Strings("accessible_permissions", accessiblePermissions),
//         util.Strings("requested_permissions", permissionNames),
//         util.Strings("final_permissions", finalPermissions),
//         util.Any("permission_bitmask", permissionBitmask))

//     s.logAdminEvent(ctx, &models.AdminLogEvent{
//         LogEnvelope: models.LogEnvelope{
//             EventID:     uuid.New().String(),
//             EventType:   "admin",
//             ServiceName: "auth-service",
//             Timestamp:   time.Now(),
//             Environment: "production",
//             Version:     "v1.0.0",
//             Level:       "info",
//             Message:     "Admin invited successfully with departments",
//         },
//         AdminID:      requesterID.String(),
//         TargetUserID: adminID.String(),
//         AdminRole:    requester.GetRoleString(),
//         Action:       "invite_admin_with_departments",
//         ResourceType: "admin_user",
//         ResourceID:   adminID.String(),
//         Status:       "success",
//         Changes: map[string]interface{}{
//             "role_mask":          roleMask,
//             "department_bitmask": deptBitmask,
//             "departments":        departmentNames,
//             "accessible_modules": modulesList,
//             "total_permissions":  len(finalPermissions),
//             "accessible_permissions_count": len(accessiblePermissions),
//             "requested_permissions_count": len(permissionNames),
//         },
//         Duration: int64(time.Since(startTime).Milliseconds()),
//     })

//     return admin, nil
// }

// func (s *AdminService) UpdateAdminDepartments(
//     ctx context.Context,
//     adminID uuid.UUID,
//     departmentNames []string,
//     updatedBy uuid.UUID,
// ) error {
//     startTime := time.Now()

//     admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Admin not found for department update",
//             },
//             AdminID:      updatedBy.String(),
//             TargetUserID: adminID.String(),
//             Action:       "update_admin_departments",
//             Status:       "failed",
//             ErrorCode:    "ADMIN_NOT_FOUND",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return fmt.Errorf("admin not found: %w", err)
//     }

//     updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Updater not found",
//             },
//             AdminID:      updatedBy.String(),
//             TargetUserID: adminID.String(),
//             Action:       "update_admin_departments",
//             Status:       "failed",
//             ErrorCode:    "UPDATER_NOT_FOUND",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return fmt.Errorf("updater not found: %w", err)
//     }

//     if !updater.IsOwner() && !(updater.IsSuperEmployee() && admin.IsEmployee()) {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "warning",
//                 Message:     "Unauthorized department update attempt",
//             },
//             AdminID:      updatedBy.String(),
//             TargetUserID: adminID.String(),
//             Action:       "update_admin_departments",
//             Status:       "failed",
//             ErrorCode:    "UNAUTHORIZED",
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return fmt.Errorf("unauthorized: cannot update this admin's departments")
//     }

//     systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to get system departments",
//             },
//             AdminID:      updatedBy.String(),
//             TargetUserID: adminID.String(),
//             Action:       "update_admin_departments",
//             Status:       "failed",
//             ErrorCode:    "GET_SYSTEM_DEPTS_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return fmt.Errorf("failed to get system departments: %w", err)
//     }

//     newDeptBitmask := uint64(0)
//     accessibleModules := make(map[string]bool)

//     for _, deptName := range departmentNames {
//         found := false
//         for _, sysDept := range systemDepartments {
//             if strings.EqualFold(sysDept.Name, deptName) {
//                 if !updater.IsOwner() && !updater.HasDepartmentAccess(sysDept.Bitmask) {
//                     s.logAdminEvent(ctx, &models.AdminLogEvent{
//                         LogEnvelope: models.LogEnvelope{
//                             EventID:     uuid.New().String(),
//                             EventType:   "admin",
//                             ServiceName: "auth-service",
//                             Timestamp:   time.Now(),
//                             Environment: "production",
//                             Version:     "v1.0.0",
//                             Level:       "warning",
//                             Message:     "Updater lacks department access",
//                         },
//                         AdminID:      updatedBy.String(),
//                         TargetUserID: adminID.String(),
//                         Action:       "update_admin_departments",
//                         Status:       "failed",
//                         ErrorCode:    "NO_DEPARTMENT_ACCESS",
//                         Duration:     int64(time.Since(startTime).Milliseconds()),
//                     })
//                     return fmt.Errorf("updater does not have access to department: %s", deptName)
//                 }
//                 newDeptBitmask |= sysDept.Bitmask
//                 accessibleModules[sysDept.ModuleCode] = true
//                 found = true
//                 break
//             }
//         }
//         if !found {
//             s.logger.Warn("Department not found", util.String("department", deptName))
//         }
//     }

//     if err := s.adminRepo.UpdateAdminDepartmentBitmask(ctx, adminID, newDeptBitmask); err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to update department bitmask",
//             },
//             AdminID:      updatedBy.String(),
//             TargetUserID: adminID.String(),
//             Action:       "update_admin_departments",
//             Status:       "failed",
//             ErrorCode:    "UPDATE_DEPARTMENT_BITMASK_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return fmt.Errorf("failed to update department bitmask: %w", err)
//     }

//     // Get permissions for new modules
//     modulesList := make([]string, 0, len(accessibleModules))
//     for module := range accessibleModules {
//         modulesList = append(modulesList, module)
//     }

//     newPermissions := make([]string, 0)
//     if len(modulesList) > 0 {
//         // Get all permissions
//         allPermissions, err := s.companyRepo.GetAllPermissions(ctx)
//         if err != nil {
//             s.logger.Warn("Failed to get all permissions",
//                 util.ErrorField(err))
//         } else {
//             // Filter permissions by modules
//             for _, perm := range allPermissions {
//                 for _, module := range modulesList {
//                     if perm.Module == module {
//                         newPermissions = append(newPermissions, perm.PermissionName)
//                         break
//                     }
//                 }
//             }
//         }
//     }

//     // Preserve existing admin permissions
//     existingPermissions := admin.GetPermissionNames()
//     for _, existingPerm := range existingPermissions {
//         if strings.HasPrefix(existingPerm, "admin.") {
//             if updater.HasPermission(existingPerm) {
//                 found := false
//                 for _, newPerm := range newPermissions {
//                     if newPerm == existingPerm {
//                         found = true
//                         break
//                     }
//                 }
//                 if !found {
//                     newPermissions = append(newPermissions, existingPerm)
//                 }
//             } else {
//                 s.logger.Warn("Updater cannot preserve admin permission they don't have",
//                     util.String("permission", existingPerm),
//                     util.String("updater_id", updatedBy.String()))
//             }
//         }
//     }

//     newPermissionMask := s.buildPermissionMask(newPermissions)

//     if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, newPermissionMask); err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to update permissions",
//             },
//             AdminID:      updatedBy.String(),
//             TargetUserID: adminID.String(),
//             Action:       "update_admin_departments",
//             Status:       "failed",
//             ErrorCode:    "UPDATE_PERMISSIONS_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return fmt.Errorf("failed to update permissions: %w", err)
//     }

//     s.logger.Info("Admin departments and permissions updated successfully",
//         util.String("admin_id", adminID.String()),
//         util.Uint64("old_department_bitmask", admin.DepartmentBitmask),
//         util.Uint64("new_department_bitmask", newDeptBitmask),
//         util.Strings("new_departments", departmentNames),
//         util.Strings("modules", modulesList),
//         util.Int("total_permissions", len(newPermissions)))

//     s.logAdminEvent(ctx, &models.AdminLogEvent{
//         LogEnvelope: models.LogEnvelope{
//             EventID:     uuid.New().String(),
//             EventType:   "admin",
//             ServiceName: "auth-service",
//             Timestamp:   time.Now(),
//             Environment: "production",
//             Version:     "v1.0.0",
//             Level:       "info",
//             Message:     "Admin departments updated successfully",
//         },
//         AdminID:      updatedBy.String(),
//         TargetUserID: adminID.String(),
//         Action:       "update_admin_departments",
//         ResourceType: "admin_user",
//         ResourceID:   adminID.String(),
//         Status:       "success",
//         Changes: map[string]interface{}{
//             "old_department_bitmask": admin.DepartmentBitmask,
//             "new_department_bitmask": newDeptBitmask,
//             "new_departments":        departmentNames,
//             "total_permissions":      len(newPermissions),
//             "modules":                modulesList,
//         },
//         Duration: int64(time.Since(startTime).Milliseconds()),
//     })

//     return nil
// }
// func (s *AdminService) buildPermissionMask(ctx context.Context, permissionNames []string) ([]uint64, error) {
// 	startTime := time.Now()
// 	permissionMask := make([]uint64, 4)
	
// 	// Get permission map from both admin and database
// 	permissionMap, err := s.getAllPermissionMap(ctx)
// 	if err != nil {
// 		s.logger.Warn("Failed to get permission map, using admin permissions only",
// 			util.ErrorField(err))
		
// 		// Fall back to only admin permissions
// 		for _, permName := range permissionNames {
// 			if bitIndex, exists := models.AdminPermissionBitIndices[permName]; exists {
// 				permissionMask = models.SetPermission(permissionMask, bitIndex, true)
// 				s.logger.Debug("Set admin permission in mask",
// 					util.String("permission", permName),
// 					util.Int("bit_index", bitIndex))
// 			} else {
// 				s.logger.Warn("Unknown permission name when building mask (admin only)",
// 					util.String("permission", permName))
// 			}
// 		}
// 		return permissionMask, nil
// 	}
	
// 	// Build permission mask with all permissions
// 	setCount := 0
// 	for _, permName := range permissionNames {
// 		if bitIndex, exists := permissionMap[permName]; exists {
// 			permissionMask = models.SetPermission(permissionMask, bitIndex, true)
// 			setCount++
// 			s.logger.Debug("Set permission in mask",
// 				util.String("permission", permName),
// 				util.Int("bit_index", bitIndex))
// 		} else {
// 			s.logger.Warn("Unknown permission name when building mask - not found in any source",
// 				util.String("permission", permName))
// 		}
// 	}
	
// 	s.logger.Debug("Permission mask built",
// 		util.Int("total_permissions", len(permissionNames)),
// 		util.Int("set_permissions", setCount),
// 		util.Any("mask", permissionMask),
// 		util.Duration("duration", time.Since(startTime)))
	
// 	return permissionMask, nil
// }
// Add this helper method to the AdminService struct
func (s *AdminService) getPermissionBitIndex(ctx context.Context, permissionName string) (int, bool) {
	// First check admin permissions
	if bitIndex, exists := models.AdminPermissionBitIndices[permissionName]; exists {
		return bitIndex, true
	}
	
	// Try to get from database
	perm, err := s.companyRepo.GetPermissionByName(ctx, permissionName)
	if err != nil {
		return -1, false
	}
	
	return perm.BitIndex, true
}

// func (s *AdminService) getAllPermissionMap(ctx context.Context) (map[string]int, error) {
// 	permissionMap := make(map[string]int)
	
// 	// Add admin permissions
// 	for permName, bitIndex := range models.AdminPermissionBitIndices {
// 		permissionMap[permName] = bitIndex
// 	}
	
// 	// Get all permissions from database
// 	allPermissions, err := s.companyRepo.GetAllPermissions(ctx)
// 	if err != nil {
// 		return permissionMap, fmt.Errorf("failed to get all permissions: %w", err)
// 	}
	
// 	// Add database permissions
// 	for _, perm := range allPermissions {
// 		permissionMap[perm.PermissionName] = perm.BitIndex
// 	}
	
// 	return permissionMap, nil
// }
func (s *AdminService) getAllPermissionMap(ctx context.Context) (map[string]int, error) {
    permissionMap := make(map[string]int)

    // Add admin permissions first
    for permName, bitIndex := range models.AdminPermissionBitIndices {
        permissionMap[permName] = bitIndex
    }

    // Get permissions with bit index from database
    permissions, err := s.companyRepo.GetPermissionsWithBitIndex(ctx)
    if err != nil {
        return permissionMap, fmt.Errorf("failed to get permissions with bit index: %w", err)
    }

    // Add database permissions
    for _, perm := range permissions {
        permissionMap[perm.Name] = perm.BitIndex
    }

    s.logger.Debug("Permission map built",
        util.Int("admin_permissions", len(models.AdminPermissionBitIndices)),
        util.Int("database_permissions", len(permissions)),
        util.Int("total_in_map", len(permissionMap)))

    return permissionMap, nil
}
// func (s *AdminService) InviteAdminWithDepartments(
//     ctx context.Context,
//     phone string,
//     roleMask uint64,
//     departmentNames []string,
//     permissionNames []string,
//     requesterID uuid.UUID,
// ) (*models.AdminUser, error) {
//     startTime := time.Now()

//     requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Requester not found for admin invitation",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "REQUESTER_NOT_FOUND",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("requester not found: %w", err)
//     }

//     if !requester.IsActive {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "warning",
//                 Message:     "Requester is not active",
//             },
//             AdminID:   requesterID.String(),
//             Action:    "invite_admin_with_departments",
//             Status:    "failed",
//             ErrorCode: "REQUESTER_INACTIVE",
//             Duration:  int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("requester is not active")
//     }

//     if !requester.CanPromoteToRole(roleMask) {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "warning",
//                 Message:     "Unauthorized role invitation attempt",
//             },
//             AdminID:   requesterID.String(),
//             Action:    "invite_admin_with_departments",
//             Status:    "failed",
//             ErrorCode: "UNAUTHORIZED_ROLE",
//             Duration:  int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("unauthorized: cannot invite to this role level")
//     }

//     phoneHash := s.GeneratePhoneHash(phone)
//     existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
//     if err == nil && existingAdmin != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "warning",
//                 Message:     "Phone already used by another admin",
//             },
//             AdminID:   requesterID.String(),
//             Action:    "invite_admin_with_departments",
//             Status:    "failed",
//             ErrorCode: "PHONE_ALREADY_ADMIN",
//             Duration:  int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("phone number is already an admin")
//     }

//     systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to get system departments",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "GET_SYSTEM_DEPTS_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("failed to get system departments: %w", err)
//     }

//     deptBitmask := uint64(0)
//     accessibleModules := make(map[string]bool)

//     for _, deptName := range departmentNames {
//         found := false
//         for _, sysDept := range systemDepartments {
//             if strings.EqualFold(sysDept.Name, deptName) {
//                 deptBitmask |= sysDept.Bitmask
//                 accessibleModules[sysDept.ModuleCode] = true
//                 found = true
//                 break
//             }
//         }
//         if !found {
//             s.logger.Warn("Department not found", util.String("department", deptName))
//         }
//     }

//     if !requester.IsOwner() {
//         for _, deptName := range departmentNames {
//             for _, sysDept := range systemDepartments {
//                 if strings.EqualFold(sysDept.Name, deptName) {
//                     if !requester.HasDepartmentAccess(sysDept.Bitmask) {
//                         s.logAdminEvent(ctx, &models.AdminLogEvent{
//                             LogEnvelope: models.LogEnvelope{
//                                 EventID:     uuid.New().String(),
//                                 EventType:   "admin",
//                                 ServiceName: "auth-service",
//                                 Timestamp:   time.Now(),
//                                 Environment: "production",
//                                 Version:     "v1.0.0",
//                                 Level:       "warning",
//                                 Message:     "Requester lacks department access",
//                             },
//                             AdminID:   requesterID.String(),
//                             Action:    "invite_admin_with_departments",
//                             Status:    "failed",
//                             ErrorCode: "NO_DEPARTMENT_ACCESS",
//                             Changes: map[string]interface{}{
//                                 "department": deptName,
//                                 "bitmask":    sysDept.Bitmask,
//                             },
//                             Duration: int64(time.Since(startTime).Milliseconds()),
//                         })
//                         return nil, fmt.Errorf("requester does not have access to department: %s", deptName)
//                     }
//                     break
//                 }
//             }
//         }
//     }

//     // Get permissions for the modules
//     accessiblePermissions := make([]string, 0)
//     modulesList := make([]string, 0, len(accessibleModules))
//     for module := range accessibleModules {
//         modulesList = append(modulesList, module)
//     }

//     if len(modulesList) > 0 {
//         // Get all permissions first
//         allPermissions, err := s.companyRepo.GetAllPermissions(ctx)
//         if err != nil {
//             s.logAdminEvent(ctx, &models.AdminLogEvent{
//                 LogEnvelope: models.LogEnvelope{
//                     EventID:     uuid.New().String(),
//                     EventType:   "admin",
//                     ServiceName: "auth-service",
//                     Timestamp:   time.Now(),
//                     Environment: "production",
//                     Version:     "v1.0.0",
//                     Level:       "error",
//                     Message:     "Failed to get all permissions",
//                 },
//                 AdminID:      requesterID.String(),
//                 Action:       "invite_admin_with_departments",
//                 Status:       "failed",
//                 ErrorCode:    "GET_ALL_PERMISSIONS_FAILED",
//                 ErrorMessage: err.Error(),
//                 Duration:     int64(time.Since(startTime).Milliseconds()),
//             })
//             return nil, fmt.Errorf("failed to get all permissions: %w", err)
//         }

//         // Filter permissions by modules
//         for _, perm := range allPermissions {
//             for _, module := range modulesList {
//                 if perm.Module == module {
//                     accessiblePermissions = append(accessiblePermissions, perm.PermissionName)
//                     break
//                 }
//             }
//         }

//         s.logger.Info("Module permissions retrieved",
//             util.Strings("modules", modulesList),
//             util.Int("total_permissions", len(accessiblePermissions)))
//     }

//     // Combine accessible permissions with requested permissions
//     finalPermissions := make([]string, 0)
    
//     // Start with accessible permissions from departments
//     finalPermissions = append(finalPermissions, accessiblePermissions...)
    
//     // Add requested permissions
//     for _, permName := range permissionNames {
//         // Check if it's an admin permission
//         if strings.HasPrefix(permName, "admin.") {
//             // Verify requester has this admin permission
//             if !requester.HasPermission(permName) {
//                 s.logAdminEvent(ctx, &models.AdminLogEvent{
//                     LogEnvelope: models.LogEnvelope{
//                         EventID:     uuid.New().String(),
//                         EventType:   "admin",
//                         ServiceName: "auth-service",
//                         Timestamp:   time.Now(),
//                         Environment: "production",
//                         Version:     "v1.0.0",
//                         Level:       "warning",
//                         Message:     "Requester lacks admin permission",
//                     },
//                     AdminID:   requesterID.String(),
//                     Action:    "invite_admin_with_departments",
//                     Status:    "failed",
//                     ErrorCode: "NO_ADMIN_PERMISSION",
//                     Changes: map[string]interface{}{
//                         "permission": permName,
//                     },
//                     Duration: int64(time.Since(startTime).Milliseconds()),
//                 })
//                 return nil, fmt.Errorf("requester does not have admin permission: %s", permName)
//             }
//         }
        
//         // Check if already in finalPermissions
//         alreadyExists := false
//         for _, p := range finalPermissions {
//             if p == permName {
//                 alreadyExists = true
//                 break
//             }
//         }
        
//         if !alreadyExists {
//             // For non-admin permissions, verify they exist in accessiblePermissions
//             if !strings.HasPrefix(permName, "admin.") {
//                 permExists := false
//                 for _, accessiblePerm := range accessiblePermissions {
//                     if permName == accessiblePerm {
//                         permExists = true
//                         break
//                     }
//                 }
//                 if !permExists {
//                     s.logger.Warn("Permission may not exist in accessible modules",
//                         util.String("permission", permName),
//                         util.String("requester_id", requesterID.String()))
//                 }
//             }
//             finalPermissions = append(finalPermissions, permName)
//         }
//     }

//     // Build permission mask
//     permissionBitmask, err := s.buildPermissionMask(ctx, finalPermissions)
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to build permission mask",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "BUILD_PERMISSION_MASK_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("failed to build permission mask: %w", err)
//     }
    
//     // Log the permission mask for debugging
//     s.logger.Info("Built permission mask",
//         util.Strings("permissions", finalPermissions),
//         util.Any("mask", permissionBitmask),
//         util.Int("segment_0", int(permissionBitmask[0])),
//         util.Int("segment_1", int(permissionBitmask[1])),
//         util.Int("segment_2", int(permissionBitmask[2])),
//         util.Int("segment_3", int(permissionBitmask[3])))

//     encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
//     if err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to encrypt phone for admin invitation",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "PHONE_ENCRYPTION_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("failed to encrypt phone: %w", err)
//     }

//     keyID, err := uuid.Parse(encryptedResult.KeyID)
//     if err != nil {
//         return nil, fmt.Errorf("failed to parse key ID: %w", err)
//     }

//     adminID := uuid.New()
//     now := time.Now().UTC()
//     admin := &models.AdminUser{
//         AdminID:             adminID,
//         PhoneHash:           phoneHash,
//         PhoneEncrypted:      encryptedResult.EncryptedValue,
//         PhoneKeyID:          keyID,
//         PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
//         AdminRoleMask:       roleMask,
//         AdminPermissionMask: permissionBitmask,
//         DepartmentBitmask:   deptBitmask,
//         AdminCreatedAt:      now,
//         AdminCreatedBy:      requesterID,
//         AdminUpdatedAt:      now,
//         IsActive:            true,
//         DataAccessScope:     s.getDefaultDataAccessScope(roleMask),
//         IPWhitelist:         []string{},
//         FailedLoginAttempts: 0,
//         LastLogin:           time.Time{},
//     }

//     if err := s.adminRepo.CreateAdmin(ctx, admin); err != nil {
//         s.logAdminEvent(ctx, &models.AdminLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   "admin",
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: "production",
//                 Version:     "v1.0.0",
//                 Level:       "error",
//                 Message:     "Failed to create admin in database",
//             },
//             AdminID:      requesterID.String(),
//             Action:       "invite_admin_with_departments",
//             Status:       "failed",
//             ErrorCode:    "CREATE_ADMIN_FAILED",
//             ErrorMessage: err.Error(),
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//         return nil, fmt.Errorf("failed to invite user as admin: %w", err)
//     }

//     // Log detailed information for debugging
//     s.logger.Info("Admin invited successfully with departments and permissions",
//         util.String("admin_id", adminID.String()),
//         util.Uint64("role_mask", roleMask),
//         util.Uint64("department_bitmask", deptBitmask),
//         util.Strings("departments", departmentNames),
//         util.Strings("accessible_modules", modulesList),
//         util.Strings("accessible_permissions", accessiblePermissions),
//         util.Strings("requested_permissions", permissionNames),
//         util.Strings("final_permissions", finalPermissions),
//         util.Any("permission_bitmask", permissionBitmask))

//     s.logAdminEvent(ctx, &models.AdminLogEvent{
//         LogEnvelope: models.LogEnvelope{
//             EventID:     uuid.New().String(),
//             EventType:   "admin",
//             ServiceName: "auth-service",
//             Timestamp:   time.Now(),
//             Environment: "production",
//             Version:     "v1.0.0",
//             Level:       "info",
//             Message:     "Admin invited successfully with departments",
//         },
//         AdminID:      requesterID.String(),
//         TargetUserID: adminID.String(),
//         AdminRole:    requester.GetRoleString(),
//         Action:       "invite_admin_with_departments",
//         ResourceType: "admin_user",
//         ResourceID:   adminID.String(),
//         Status:       "success",
//         Changes: map[string]interface{}{
//             "role_mask":          roleMask,
//             "department_bitmask": deptBitmask,
//             "departments":        departmentNames,
//             "accessible_modules": modulesList,
//             "total_permissions":  len(finalPermissions),
//             "accessible_permissions_count": len(accessiblePermissions),
//             "requested_permissions_count": len(permissionNames),
//         },
//         Duration: int64(time.Since(startTime).Milliseconds()),
//     })

//     return admin, nil
// }


func (s *AdminService) UpdateAdminDepartments(
    ctx context.Context,
    adminID uuid.UUID,
    departmentNames []string,
    updatedBy uuid.UUID,
) error {
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
                Message:     "Admin not found for department update",
            },
            AdminID:      updatedBy.String(),
            TargetUserID: adminID.String(),
            Action:       "update_admin_departments",
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
            TargetUserID: adminID.String(),
            Action:       "update_admin_departments",
            Status:       "failed",
            ErrorCode:    "UPDATER_NOT_FOUND",
            ErrorMessage: err.Error(),
            Duration:     int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("updater not found: %w", err)
    }

    if !updater.IsOwner() && !(updater.IsSuperEmployee() && admin.IsEmployee()) {
        s.logAdminEvent(ctx, &models.AdminLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "admin",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "warning",
                Message:     "Unauthorized department update attempt",
            },
            AdminID:      updatedBy.String(),
            TargetUserID: adminID.String(),
            Action:       "update_admin_departments",
            Status:       "failed",
            ErrorCode:    "UNAUTHORIZED",
            Duration:     int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("unauthorized: cannot update this admin's departments")
    }

    systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
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
                Message:     "Failed to get system departments",
            },
            AdminID:      updatedBy.String(),
            TargetUserID: adminID.String(),
            Action:       "update_admin_departments",
            Status:       "failed",
            ErrorCode:    "GET_SYSTEM_DEPTS_FAILED",
            ErrorMessage: err.Error(),
            Duration:     int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("failed to get system departments: %w", err)
    }

    newDeptBitmask := uint64(0)
    accessibleModules := make(map[string]bool)

    for _, deptName := range departmentNames {
        found := false
        for _, sysDept := range systemDepartments {
            if strings.EqualFold(sysDept.Name, deptName) {
                if !updater.IsOwner() && !updater.HasDepartmentAccess(sysDept.Bitmask) {
                    s.logAdminEvent(ctx, &models.AdminLogEvent{
                        LogEnvelope: models.LogEnvelope{
                            EventID:     uuid.New().String(),
                            EventType:   "admin",
                            ServiceName: "auth-service",
                            Timestamp:   time.Now(),
                            Environment: "production",
                            Version:     "v1.0.0",
                            Level:       "warning",
                            Message:     "Updater lacks department access",
                        },
                        AdminID:      updatedBy.String(),
                        TargetUserID: adminID.String(),
                        Action:       "update_admin_departments",
                        Status:       "failed",
                        ErrorCode:    "NO_DEPARTMENT_ACCESS",
                        Duration:     int64(time.Since(startTime).Milliseconds()),
                    })
                    return fmt.Errorf("updater does not have access to department: %s", deptName)
                }
                newDeptBitmask |= sysDept.Bitmask
                accessibleModules[sysDept.ModuleCode] = true
                found = true
                break
            }
        }
        if !found {
            s.logger.Warn("Department not found", util.String("department", deptName))
        }
    }

    if err := s.adminRepo.UpdateAdminDepartmentBitmask(ctx, adminID, newDeptBitmask); err != nil {
        s.logAdminEvent(ctx, &models.AdminLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "admin",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "error",
                Message:     "Failed to update department bitmask",
            },
            AdminID:      updatedBy.String(),
            TargetUserID: adminID.String(),
            Action:       "update_admin_departments",
            Status:       "failed",
            ErrorCode:    "UPDATE_DEPARTMENT_BITMASK_FAILED",
            ErrorMessage: err.Error(),
            Duration:     int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("failed to update department bitmask: %w", err)
    }

    // Get permissions for new modules
    modulesList := make([]string, 0, len(accessibleModules))
    for module := range accessibleModules {
        modulesList = append(modulesList, module)
    }

    newPermissions := make([]string, 0)
    if len(modulesList) > 0 {
        // Get all permissions
        allPermissions, err := s.companyRepo.GetAllPermissions(ctx)
        if err != nil {
            s.logger.Warn("Failed to get all permissions",
                util.ErrorField(err))
        } else {
            // Filter permissions by modules
            for _, perm := range allPermissions {
                for _, module := range modulesList {
                    if perm.Module == module {
                        newPermissions = append(newPermissions, perm.PermissionName)
                        break
                    }
                }
            }
        }
    }

    // Preserve existing admin permissions
    existingPermissions := admin.GetPermissionNames()
    for _, existingPerm := range existingPermissions {
        if strings.HasPrefix(existingPerm, "admin.") {
            if updater.HasPermission(existingPerm) {
                found := false
                for _, newPerm := range newPermissions {
                    if newPerm == existingPerm {
                        found = true
                        break
                    }
                }
                if !found {
                    newPermissions = append(newPermissions, existingPerm)
                }
            } else {
                s.logger.Warn("Updater cannot preserve admin permission they don't have",
                    util.String("permission", existingPerm),
                    util.String("updater_id", updatedBy.String()))
            }
        }
    }

    // Build new permission mask
    newPermissionMask, err := s.buildPermissionMask(ctx, newPermissions)
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
                Message:     "Failed to build permission mask",
            },
            AdminID:      updatedBy.String(),
            TargetUserID: adminID.String(),
            Action:       "update_admin_departments",
            Status:       "failed",
            ErrorCode:    "BUILD_PERMISSION_MASK_FAILED",
            ErrorMessage: err.Error(),
            Duration:     int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("failed to build permission mask: %w", err)
    }
    
    // Log the new permission mask for debugging
    s.logger.Info("Built new permission mask for update",
        util.String("admin_id", adminID.String()),
        util.Strings("permissions", newPermissions),
        util.Any("mask", newPermissionMask),
        util.Int("segment_0", int(newPermissionMask[0])),
        util.Int("segment_1", int(newPermissionMask[1])),
        util.Int("segment_2", int(newPermissionMask[2])),
        util.Int("segment_3", int(newPermissionMask[3])))
    
    if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, newPermissionMask); err != nil {
        s.logAdminEvent(ctx, &models.AdminLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "admin",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "error",
                Message:     "Failed to update permissions",
            },
            AdminID:      updatedBy.String(),
            TargetUserID: adminID.String(),
            Action:       "update_admin_departments",
            Status:       "failed",
            ErrorCode:    "UPDATE_PERMISSIONS_FAILED",
            ErrorMessage: err.Error(),
            Duration:     int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("failed to update permissions: %w", err)
    }

    s.logger.Info("Admin departments and permissions updated successfully",
        util.String("admin_id", adminID.String()),
        util.Uint64("old_department_bitmask", admin.DepartmentBitmask),
        util.Uint64("new_department_bitmask", newDeptBitmask),
        util.Strings("new_departments", departmentNames),
        util.Strings("modules", modulesList),
        util.Int("total_permissions", len(newPermissions)))

    s.logAdminEvent(ctx, &models.AdminLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   "admin",
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: "production",
            Version:     "v1.0.0",
            Level:       "info",
            Message:     "Admin departments updated successfully",
        },
        AdminID:      updatedBy.String(),
        TargetUserID: adminID.String(),
        Action:       "update_admin_departments",
        ResourceType: "admin_user",
        ResourceID:   adminID.String(),
        Status:       "success",
        Changes: map[string]interface{}{
            "old_department_bitmask": admin.DepartmentBitmask,
            "new_department_bitmask": newDeptBitmask,
            "new_departments":        departmentNames,
            "total_permissions":      len(newPermissions),
            "modules":                modulesList,
        },
        Duration: int64(time.Since(startTime).Milliseconds()),
    })

    return nil
}

func (s *AdminService) buildPermissionMask(ctx context.Context, permissionNames []string) ([]uint64, error) {
    startTime := time.Now()
    permissionMask := make([]uint64, 4)
    
    // Debug: Print all permissions being processed
    s.logger.Info("Building permission mask for permissions",
        util.Strings("permission_names", permissionNames))
    
    permissionMap, err := s.getAllPermissionMap(ctx)
    if err != nil {
        s.logger.Warn("Failed to get permission map, using admin permissions only",
            util.ErrorField(err))
        
        // Debug: Show admin permission indices
        for permName, bitIndex := range models.AdminPermissionBitIndices {
            s.logger.Debug("Admin permission mapping",
                util.String("permission", permName),
                util.Int("bit_index", bitIndex))
        }
        
        for _, permName := range permissionNames {
            if bitIndex, exists := models.AdminPermissionBitIndices[permName]; exists {
                permissionMask = models.SetPermission(permissionMask, bitIndex, true)
                s.logger.Debug("Set admin permission in mask",
                    util.String("permission", permName),
                    util.Int("bit_index", bitIndex))
            } else {
                s.logger.Warn("Unknown permission name when building mask (admin only)",
                    util.String("permission", permName))
            }
        }
        return permissionMask, nil
    }
    
    // Debug: Show permission map entries for the requested permissions
    for _, permName := range permissionNames {
        if bitIndex, exists := permissionMap[permName]; exists {
            s.logger.Debug("Found permission in map",
                util.String("permission", permName),
                util.Int("bit_index", bitIndex))
        } else {
            s.logger.Warn("Permission not found in permission map",
                util.String("permission", permName))
        }
    }
    
    setCount := 0
    for _, permName := range permissionNames {
        if bitIndex, exists := permissionMap[permName]; exists {
            permissionMask = models.SetPermission(permissionMask, bitIndex, true)
            setCount++
            s.logger.Debug("Set permission in mask",
                util.String("permission", permName),
                util.Int("bit_index", bitIndex))
        } else {
            s.logger.Warn("Unknown permission name when building mask - not found in any source",
                util.String("permission", permName))
        }
    }
    
    s.logger.Info("Permission mask built",
        util.Int("total_permissions", len(permissionNames)),
        util.Int("set_permissions", setCount),
        util.Any("mask", permissionMask),
        util.Uint64("mask_0", permissionMask[0]),
        util.Uint64("mask_1", permissionMask[1]),
        util.Uint64("mask_2", permissionMask[2]),
        util.Uint64("mask_3", permissionMask[3]),
        util.Duration("duration", time.Since(startTime)))
    
    return permissionMask, nil
}



// InviteAdminWithDepartments invites a new admin with specific departments and permissions
func (s *AdminService) InviteAdminWithDepartments(
    ctx context.Context,
    phone string,
    roleMask uint64,
    departmentNames []string,
    permissionNames []string,
    requesterID uuid.UUID,
) (*models.AdminUser, error) {
    startTime := time.Now()

    // BLOCK INVITING AS OWNER
    if roleMask == models.RoleMaskOwner {
        s.logAdminEvent(ctx, &models.AdminLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "admin",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "error",
                Message:     "Cannot invite user as owner",
            },
            AdminID:      requesterID.String(),
            Action:       "invite_admin_with_departments",
            Status:       "failed",
            ErrorCode:    "CANNOT_INVITE_AS_OWNER",
            ErrorMessage: "Cannot invite user as owner. Owner can only be created via system initialization.",
            Duration:     int64(time.Since(startTime).Milliseconds()),
        })
        return nil, fmt.Errorf("cannot invite user as owner. Owner can only be created via system initialization")
    }

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
                Message:     "Requester not found for admin invitation",
            },
            AdminID:      requesterID.String(),
            Action:       "invite_admin_with_departments",
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
            AdminID:   requesterID.String(),
            Action:    "invite_admin_with_departments",
            Status:    "failed",
            ErrorCode: "REQUESTER_INACTIVE",
            Duration:  int64(time.Since(startTime).Milliseconds()),
        })
        return nil, fmt.Errorf("requester is not active")
    }

    if !requester.CanPromoteToRole(roleMask) {
        s.logAdminEvent(ctx, &models.AdminLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "admin",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "warning",
                Message:     "Unauthorized role invitation attempt",
            },
            AdminID:   requesterID.String(),
            Action:    "invite_admin_with_departments",
            Status:    "failed",
            ErrorCode: "UNAUTHORIZED_ROLE",
            Duration:  int64(time.Since(startTime).Milliseconds()),
        })
        return nil, fmt.Errorf("unauthorized: cannot invite to this role level")
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
                Message:     "Phone already used by another admin",
            },
            AdminID:   requesterID.String(),
            Action:    "invite_admin_with_departments",
            Status:    "failed",
            ErrorCode: "PHONE_ALREADY_ADMIN",
            Duration:  int64(time.Since(startTime).Milliseconds()),
        })
        return nil, fmt.Errorf("phone number is already an admin")
    }

    systemDepartments, err := s.companyRepo.GetSystemDepartments(ctx)
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
                Message:     "Failed to get system departments",
            },
            AdminID:      requesterID.String(),
            Action:       "invite_admin_with_departments",
            Status:       "failed",
            ErrorCode:    "GET_SYSTEM_DEPTS_FAILED",
            ErrorMessage: err.Error(),
            Duration:     int64(time.Since(startTime).Milliseconds()),
        })
        return nil, fmt.Errorf("failed to get system departments: %w", err)
    }

    deptBitmask := uint64(0)
    accessibleModules := make(map[string]bool)

    for _, deptName := range departmentNames {
        found := false
        for _, sysDept := range systemDepartments {
            if strings.EqualFold(sysDept.Name, deptName) {
                deptBitmask |= sysDept.Bitmask
                accessibleModules[sysDept.ModuleCode] = true
                found = true
                break
            }
        }
        if !found {
            s.logger.Warn("Department not found", util.String("department", deptName))
        }
    }

    if !requester.IsOwner() {
        for _, deptName := range departmentNames {
            for _, sysDept := range systemDepartments {
                if strings.EqualFold(sysDept.Name, deptName) {
                    if !requester.HasDepartmentAccess(sysDept.Bitmask) {
                        s.logAdminEvent(ctx, &models.AdminLogEvent{
                            LogEnvelope: models.LogEnvelope{
                                EventID:     uuid.New().String(),
                                EventType:   "admin",
                                ServiceName: "auth-service",
                                Timestamp:   time.Now(),
                                Environment: "production",
                                Version:     "v1.0.0",
                                Level:       "warning",
                                Message:     "Requester lacks department access",
                            },
                            AdminID:   requesterID.String(),
                            Action:    "invite_admin_with_departments",
                            Status:    "failed",
                            ErrorCode: "NO_DEPARTMENT_ACCESS",
                            Changes: map[string]interface{}{
                                "department": deptName,
                                "bitmask":    sysDept.Bitmask,
                            },
                            Duration: int64(time.Since(startTime).Milliseconds()),
                        })
                        return nil, fmt.Errorf("requester does not have access to department: %s", deptName)
                    }
                    break
                }
            }
        }
    }

    // Get permissions for the modules
    accessiblePermissions := make([]string, 0)
    modulesList := make([]string, 0, len(accessibleModules))
    for module := range accessibleModules {
        modulesList = append(modulesList, module)
    }

    if len(modulesList) > 0 {
        // Get all permissions
        allPermissions, err := s.companyRepo.GetAllPermissions(ctx)
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
                    Message:     "Failed to get all permissions",
                },
                AdminID:      requesterID.String(),
                Action:       "invite_admin_with_departments",
                Status:       "failed",
                ErrorCode:    "GET_ALL_PERMISSIONS_FAILED",
                ErrorMessage: err.Error(),
                Duration:     int64(time.Since(startTime).Milliseconds()),
            })
            return nil, fmt.Errorf("failed to get all permissions: %w", err)
        }

        // Filter permissions by modules
        for _, perm := range allPermissions {
            for _, module := range modulesList {
                if perm.Module == module {
                    accessiblePermissions = append(accessiblePermissions, perm.PermissionName)
                    break
                }
            }
        }

        s.logger.Info("Module permissions retrieved",
            util.Strings("modules", modulesList),
            util.Int("total_permissions", len(accessiblePermissions)))
    }

    // Combine accessible permissions with requested permissions
    finalPermissions := make([]string, 0)
    
    // Start with accessible permissions from departments
    finalPermissions = append(finalPermissions, accessiblePermissions...)
    
    // Add requested permissions
    for _, permName := range permissionNames {
        // Check if it's an admin permission
        if strings.HasPrefix(permName, "admin.") {
            // Verify requester has this admin permission
            if !requester.HasPermission(permName) {
                s.logAdminEvent(ctx, &models.AdminLogEvent{
                    LogEnvelope: models.LogEnvelope{
                        EventID:     uuid.New().String(),
                        EventType:   "admin",
                        ServiceName: "auth-service",
                        Timestamp:   time.Now(),
                        Environment: "production",
                        Version:     "v1.0.0",
                        Level:       "warning",
                        Message:     "Requester lacks admin permission",
                    },
                    AdminID:   requesterID.String(),
                    Action:    "invite_admin_with_departments",
                    Status:    "failed",
                    ErrorCode: "NO_ADMIN_PERMISSION",
                    Changes: map[string]interface{}{
                        "permission": permName,
                    },
                    Duration: int64(time.Since(startTime).Milliseconds()),
                })
                return nil, fmt.Errorf("requester does not have admin permission: %s", permName)
            }
        }
        
        // Check if already in finalPermissions
        alreadyExists := false
        for _, p := range finalPermissions {
            if p == permName {
                alreadyExists = true
                break
            }
        }
        
        if !alreadyExists {
            // For non-admin permissions, verify they exist in accessiblePermissions
            if !strings.HasPrefix(permName, "admin.") {
                permExists := false
                for _, accessiblePerm := range accessiblePermissions {
                    if permName == accessiblePerm {
                        permExists = true
                        break
                    }
                }
                if !permExists {
                    s.logger.Warn("Permission may not exist in accessible modules",
                        util.String("permission", permName),
                        util.String("requester_id", requesterID.String()))
                }
            }
            finalPermissions = append(finalPermissions, permName)
        }
    }

    // Build permission mask
    permissionBitmask, err := s.buildPermissionMask(ctx, finalPermissions)
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
                Message:     "Failed to build permission mask",
            },
            AdminID:      requesterID.String(),
            Action:       "invite_admin_with_departments",
            Status:       "failed",
            ErrorCode:    "BUILD_PERMISSION_MASK_FAILED",
            ErrorMessage: err.Error(),
            Duration:     int64(time.Since(startTime).Milliseconds()),
        })
        return nil, fmt.Errorf("failed to build permission mask: %w", err)
    }
    
    // Log the permission mask for debugging
    s.logger.Info("Built permission mask",
        util.Strings("permissions", finalPermissions),
        util.Any("mask", permissionBitmask),
        util.Int("segment_0", int(permissionBitmask[0])),
        util.Int("segment_1", int(permissionBitmask[1])),
        util.Int("segment_2", int(permissionBitmask[2])),
        util.Int("segment_3", int(permissionBitmask[3])))

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
                Message:     "Failed to encrypt phone for admin invitation",
            },
            AdminID:      requesterID.String(),
            Action:       "invite_admin_with_departments",
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

    adminID := uuid.New()
    now := time.Now().UTC()
    admin := &models.AdminUser{
        AdminID:             adminID,
        PhoneHash:           phoneHash,
        PhoneEncrypted:      encryptedResult.EncryptedValue,
        PhoneKeyID:          keyID,
        PhoneEncryptedDEK:   encryptedResult.EncryptedDEK,
        AdminRoleMask:       roleMask,
        AdminPermissionMask: permissionBitmask,
        DepartmentBitmask:   deptBitmask,
        AdminCreatedAt:      now,
        AdminCreatedBy:      requesterID,
        AdminUpdatedAt:      now,
        IsActive:            true,
        DataAccessScope:     s.getDefaultDataAccessScope(roleMask),
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
            Action:       "invite_admin_with_departments",
            Status:       "failed",
            ErrorCode:    "CREATE_ADMIN_FAILED",
            ErrorMessage: err.Error(),
            Duration:     int64(time.Since(startTime).Milliseconds()),
        })
        return nil, fmt.Errorf("failed to invite user as admin: %w", err)
    }

    // Log detailed information for debugging
    s.logger.Info("Admin invited successfully with departments and permissions",
        util.String("admin_id", adminID.String()),
        util.Uint64("role_mask", roleMask),
        util.Uint64("department_bitmask", deptBitmask),
        util.Strings("departments", departmentNames),
        util.Strings("accessible_modules", modulesList),
        util.Strings("accessible_permissions", accessiblePermissions),
        util.Strings("requested_permissions", permissionNames),
        util.Strings("final_permissions", finalPermissions),
        util.Any("permission_bitmask", permissionBitmask))

    s.logAdminEvent(ctx, &models.AdminLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   "admin",
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: "production",
            Version:     "v1.0.0",
            Level:       "info",
            Message:     "Admin invited successfully with departments",
        },
        AdminID:      requesterID.String(),
        TargetUserID: adminID.String(),
        AdminRole:    requester.GetRoleString(),
        Action:       "invite_admin_with_departments",
        ResourceType: "admin_user",
        ResourceID:   adminID.String(),
        Status:       "success",
        Changes: map[string]interface{}{
            "role_mask":                      roleMask,
            "department_bitmask":             deptBitmask,
            "departments":                    departmentNames,
            "accessible_modules":             modulesList,
            "total_permissions":              len(finalPermissions),
            "accessible_permissions_count":   len(accessiblePermissions),
            "requested_permissions_count":    len(permissionNames),
        },
        Duration: int64(time.Since(startTime).Milliseconds()),
    })

    return admin, nil
}
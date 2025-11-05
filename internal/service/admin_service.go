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
    adminRepo     scylla.AdminRepository
    userRepo      scylla.UserRepository
    sessionService *SessionService
    hasher        *hashing.Hasher
    encryptionMgr *encryption.EncryptionManager
    logProducer   *LogProducerService  // ✅ ADD KAFKA LOG PRODUCER
    logger        *zap.Logger
}

// NewAdminService creates admin service with injected dependencies
func NewAdminService(
    adminRepo scylla.AdminRepository,
    userRepo scylla.UserRepository,
    sessionService *SessionService,
    hasher *hashing.Hasher,
    encryptionMgr *encryption.EncryptionManager,
    logger *zap.Logger,
) *AdminService {
    return &AdminService{
        adminRepo:      adminRepo,
        userRepo:       userRepo,
        sessionService: sessionService,
        hasher:         hasher,
        encryptionMgr:  encryptionMgr,
        logger:         logger,
    }
}

// ✅ ADD LOG PRODUCER SETTER METHOD
func (s *AdminService) SetLogProducerService(logProducer *LogProducerService) {
    s.logProducer = logProducer
}

// GeneratePhoneHash generates a secure hash of phone number (same as UserService)
func (s *AdminService) GeneratePhoneHash(phoneNumber string) string {
    normalized := strings.ReplaceAll(phoneNumber, " ", "")
    normalized = strings.ReplaceAll(normalized, "-", "")
    normalized = strings.ReplaceAll(normalized, "(", "")
    normalized = strings.ReplaceAll(normalized, ")", "")

    hash := sha256.Sum256([]byte(normalized))
    return hex.EncodeToString(hash[:])
}

// InitializeOwner creates the first owner of the system
func (s *AdminService) InitializeOwner(ctx context.Context, phone string) (*models.AdminUser, error) {
    startTime := time.Now()

    exists, err := s.adminRepo.IsOwnerExists(ctx)
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
                LogEnvelope: models.LogEnvelope{
                    EventID:     uuid.New().String(),
                    EventType:   "admin",
                    ServiceName: "auth-service",
                    Timestamp:   time.Now(),
                    Environment: "production", // This should come from config
                    Version:     "v1.0.0",
                    Level:       "error",
                    Message:     "Failed to check owner existence",
                },
                Action:    "initialize_owner",
                Status:    "failed",
                ErrorCode: "CHECK_OWNER_EXISTS_FAILED",
                ErrorMessage: err.Error(),
                Duration:  int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, fmt.Errorf("failed to check owner existence: %w", err)
    }
    if exists {
        // ✅ LOG FAILURE EVENT - OWNER ALREADY EXISTS
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, fmt.Errorf("system already has an owner")
    }

    // Hash and encrypt phone in service layer
    phoneHash := s.GeneratePhoneHash(phone)
    encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                Action:    "initialize_owner",
                Status:    "failed",
                ErrorCode: "PHONE_ENCRYPTION_FAILED",
                ErrorMessage: err.Error(),
                Duration:  int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
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
        AdminRoleLevel:    models.RoleLevelOwner,
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
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                Action:    "initialize_owner",
                Status:    "failed",
                ErrorCode: "CREATE_OWNER_FAILED",
                ErrorMessage: err.Error(),
                Duration:  int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, fmt.Errorf("failed to create owner: %w", err)
    }

    // ✅ LOG SUCCESS EVENT
    if s.logProducer != nil {
        event := &models.AdminLogEvent{
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
            AdminID:    ownerID.String(),
            AdminRole:  models.RoleLevelOwner,
            Action:     "initialize_owner",
            Status:     "success",
            Duration:   int64(time.Since(startTime).Milliseconds()),
        }
        _ = s.logProducer.ProduceAdminEvent(ctx, event)
    }

    s.logger.Info("Owner initialized", util.String("admin_id", owner.AdminID.String()))

    return owner, nil
}

// ChangeOwnerPhone allows owner to update their phone
func (s *AdminService) ChangeOwnerPhone(ctx context.Context, ownerID uuid.UUID, newPhone string) error {
    startTime := time.Now()

    // ✅ Input validation first
    if ownerID == uuid.Nil {
        return fmt.Errorf("invalid owner ID")
    }
    if newPhone == "" {
        return fmt.Errorf("new phone cannot be empty")
    }

    s.logger.Info("ChangeOwnerPhone called",
        util.String("owner_id", ownerID.String()),
        util.String("new_phone", newPhone),
    )

    // ✅ Get owner with proper nil handling
    owner, err := s.adminRepo.GetOwner(ctx)
    if err != nil {
        s.logger.Error("Failed to get owner from repository",
            util.String("owner_id", ownerID.String()),
            util.ErrorField(err),
        )
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    ownerID.String(),
                Action:     "change_owner_phone",
                Status:     "failed",
                ErrorCode:  "GET_OWNER_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("failed to get owner: %w", err)
    }

    // ✅ CRITICAL: Check if owner is nil
    if owner == nil {
        s.logger.Error("Owner not found in database",
            util.String("owner_id", ownerID.String()),
        )
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    ownerID.String(),
                Action:     "change_owner_phone",
                Status:     "failed",
                ErrorCode:  "OWNER_NOT_FOUND",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("owner not found in system")
    }

    s.logger.Info("Owner found",
        util.String("owner_id", owner.AdminID.String()),
        util.String("owner_role", owner.AdminRoleLevel),
    )

    // ✅ Now safely check if the requester is the actual owner
    if owner.AdminID != ownerID {
        s.logger.Warn("Unauthorized phone change attempt",
            util.String("requester_id", ownerID.String()),
            util.String("actual_owner_id", owner.AdminID.String()),
        )
        // ✅ LOG FAILURE EVENT - UNAUTHORIZED
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    ownerID.String(),
                Action:     "change_owner_phone",
                Status:     "failed",
                ErrorCode:  "UNAUTHORIZED",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("unauthorized: only owner can change phone")
    }

    newPhoneHash := s.GeneratePhoneHash(newPhone)
    
    // ✅ Check if new phone is same as current
    if owner.PhoneHash == newPhoneHash {
        return fmt.Errorf("new phone is the same as current phone")
    }

    // ✅ Check if new phone is already used by another admin
    existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, newPhoneHash)
    if err == nil && existingAdmin != nil && existingAdmin.AdminID != ownerID {
        // ✅ LOG FAILURE EVENT - PHONE ALREADY USED
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    ownerID.String(),
                Action:     "change_owner_phone",
                Status:     "failed",
                ErrorCode:  "PHONE_ALREADY_USED",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("phone number is already used by another admin")
    }

    encryptedResult, err := s.encryptionMgr.EncryptField(ctx, newPhone, "phone")
    if err != nil {
        s.logger.Error("Failed to encrypt new phone",
            util.String("owner_id", ownerID.String()),
            util.ErrorField(err),
        )
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    ownerID.String(),
                Action:     "change_owner_phone",
                Status:     "failed",
                ErrorCode:  "PHONE_ENCRYPTION_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("failed to encrypt new phone: %w", err)
    }

    keyID, err := uuid.Parse(encryptedResult.KeyID)
    if err != nil {
        return fmt.Errorf("failed to parse key ID: %w", err)
    }

    s.logger.Info("Phone encryption completed",
        util.String("key_id", keyID.String()),
        util.Int("encrypted_length", len(encryptedResult.EncryptedValue)),
    )

    // ✅ Use the new UpdateOwnerPhone method that handles encrypted fields
    if err := s.adminRepo.UpdateOwnerPhone(ctx, ownerID, newPhoneHash, encryptedResult.EncryptedValue, keyID, encryptedResult.EncryptedDEK); err != nil {
        s.logger.Error("Failed to update owner phone in repository",
            util.String("owner_id", ownerID.String()),
            util.ErrorField(err),
        )
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    ownerID.String(),
                Action:     "change_owner_phone",
                Status:     "failed",
                ErrorCode:  "UPDATE_PHONE_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("failed to update owner phone: %w", err)
    }

    // ✅ LOG SUCCESS EVENT
    if s.logProducer != nil {
        event := &models.AdminLogEvent{
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
            AdminID:  ownerID.String(),
            AdminRole: models.RoleLevelOwner,
            Action:   "change_owner_phone",
            Status:   "success",
            Duration: int64(time.Since(startTime).Milliseconds()),
        }
        _ = s.logProducer.ProduceAdminEvent(ctx, event)
    }

    s.logger.Info("Owner phone updated successfully",
        util.String("admin_id", ownerID.String()),
        util.String("new_phone_hash", newPhoneHash),
    )

    return nil
}

// InviteAdmin invites a user as admin - NO USER REGISTRATION CHECK
func (s *AdminService) InviteAdmin(ctx context.Context, phone string, roleLevel string, requesterID uuid.UUID, requesterRole string) (*models.AdminUser, error) {
    startTime := time.Now()

    requester, err := s.adminRepo.GetAdminByID(ctx, requesterID)
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    requesterID.String(),
                Action:     "invite_admin",
                Status:     "failed",
                ErrorCode:  "REQUESTER_NOT_FOUND",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, fmt.Errorf("requester not found: %w", err)
    }
    if !requester.IsActive {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    requesterID.String(),
                Action:     "invite_admin",
                Status:     "failed",
                ErrorCode:  "REQUESTER_INACTIVE",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, fmt.Errorf("requester is not active")
    }

    // ✅ FIXED: Validate role-based permissions
    if requester.IsEmployee() {
        // ✅ LOG FAILURE EVENT - UNAUTHORIZED
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    requesterID.String(),
                Action:     "invite_admin",
                Status:     "failed",
                ErrorCode:  "UNAUTHORIZED",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, fmt.Errorf("employees cannot invite admins")
    }
    if requester.IsSuperEmployee() && roleLevel != models.RoleLevelEmployee {
        // ✅ LOG FAILURE EVENT - UNAUTHORIZED
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    requesterID.String(),
                Action:     "invite_admin",
                Status:     "failed",
                ErrorCode:  "UNAUTHORIZED",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, fmt.Errorf("super employees can only invite as employee")
    }

    phoneHash := s.GeneratePhoneHash(phone)
    
    // ✅ Check if phone is already an admin
    existingAdmin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
    if err == nil && existingAdmin != nil {
        // ✅ LOG FAILURE EVENT - PHONE ALREADY ADMIN
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    requesterID.String(),
                Action:     "invite_admin",
                Status:     "failed",
                ErrorCode:  "PHONE_ALREADY_ADMIN",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, fmt.Errorf("phone number is already an admin")
    }

    encryptedResult, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    requesterID.String(),
                Action:     "invite_admin",
                Status:     "failed",
                ErrorCode:  "PHONE_ENCRYPTION_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, fmt.Errorf("failed to encrypt phone: %w", err)
    }

    keyID, err := uuid.Parse(encryptedResult.KeyID)
    if err != nil {
        return nil, fmt.Errorf("failed to parse key ID: %w", err)
    }

    // ❌ REMOVED: User registration check - admin accounts are independent

    permissions := s.getPermissionsForRole(roleLevel)

    adminID := uuid.New()
    now := time.Now().UTC()
    admin := &models.AdminUser{
        AdminID:           adminID,
        PhoneHash:         phoneHash,
        PhoneEncrypted:    encryptedResult.EncryptedValue,
        PhoneKeyID:        keyID,
        PhoneEncryptedDEK: encryptedResult.EncryptedDEK,
        AdminRoleLevel:    roleLevel,
        AdminPermissions:  permissions,
        AdminCreatedAt:    now,
        AdminCreatedBy:    requesterID,
        AdminUpdatedAt:    now,
        IsActive:          true,
        DataAccessScope:   s.getDefaultDataAccessScope(roleLevel),
        IPWhitelist:       []string{},
        FailedLoginAttempts: 0,
        LastLogin:         time.Time{},
    }

    if err := s.adminRepo.CreateAdmin(ctx, admin); err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    requesterID.String(),
                Action:     "invite_admin",
                Status:     "failed",
                ErrorCode:  "CREATE_ADMIN_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, fmt.Errorf("failed to invite user as admin: %w", err)
    }

    // ✅ LOG SUCCESS EVENT
    if s.logProducer != nil {
        event := &models.AdminLogEvent{
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
            AdminID:        adminID.String(),
            AdminRole:      roleLevel,
            TargetUserID:   phone, // Using phone as target identifier
            Action:         "invite_admin",
            ResourceType:   "admin_user",
            ResourceID:     adminID.String(),
            Status:         "success",
            Duration:       int64(time.Since(startTime).Milliseconds()),
        }
        _ = s.logProducer.ProduceAdminEvent(ctx, event)
    }

    s.logger.Info("User invited as admin",
        util.String("admin_id", admin.AdminID.String()),
        util.String("phone", phone),
        util.String("role_level", roleLevel),
        util.String("invited_by", requesterID.String()),
    )

    return admin, nil
}

// GetAdminByPhone retrieves admin by phone, hashing phone before lookup
func (s *AdminService) GetAdminByPhone(ctx context.Context, phone string) (*models.AdminUser, error) {
    phoneHash := s.GeneratePhoneHash(phone)
    return s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
}

// AuthenticateAdmin authenticates an admin by phone - ONLY CHECKS ADMIN TABLE
func (s *AdminService) AuthenticateAdmin(ctx context.Context, phone string) (*models.AdminUser, error) {
    startTime := time.Now()

    phoneHash := s.GeneratePhoneHash(phone)
    admin, err := s.adminRepo.GetAdminByPhoneHash(ctx, phoneHash)
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, fmt.Errorf("authentication failed: %w", err)
    }
    if !admin.IsActive {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    admin.AdminID.String(),
                Action:     "authenticate_admin",
                Status:     "failed",
                ErrorCode:  "ACCOUNT_DEACTIVATED",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, fmt.Errorf("admin account is deactivated")
    }
    if err := s.adminRepo.UpdateLastLogin(ctx, admin.AdminID); err != nil {
        s.logger.Warn("Failed to update last login",
            util.String("admin_id", admin.AdminID.String()),
            util.ErrorField(err),
        )
    }

    // ✅ LOG SUCCESS EVENT
    if s.logProducer != nil {
        event := &models.AdminLogEvent{
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
        }
        _ = s.logProducer.ProduceAdminEvent(ctx, event)
    }

    return admin, nil
}

// ===== HELPER METHODS =====

// getDefaultDataAccessScope returns default data access scope for role
func (s *AdminService) getDefaultDataAccessScope(roleLevel string) []string {
    switch roleLevel {
    case models.RoleLevelOwner, models.RoleLevelSuperEmployee:
        return []string{models.DataAccessGlobal}
    case models.RoleLevelEmployee:
        return []string{models.DataAccessGlobal}
    default:
        return []string{models.DataAccessGlobal}
    }
}

// PromoteAdmin promotes an admin to higher role
func (s *AdminService) PromoteAdmin(ctx context.Context, adminID uuid.UUID, newRole string, promotedBy uuid.UUID) error {
    startTime := time.Now()

    // Get current admin
    admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    promotedBy.String(),
                Action:     "promote_admin",
                Status:     "failed",
                ErrorCode:  "ADMIN_NOT_FOUND",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("admin not found: %w", err)
    }

    // Get promoter
    promoter, err := s.adminRepo.GetAdminByID(ctx, promotedBy)
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    promotedBy.String(),
                Action:     "promote_admin",
                Status:     "failed",
                ErrorCode:  "PROMOTER_NOT_FOUND",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("promoter not found: %w", err)
    }

    // Check permission to promote
    if !promoter.CanPromoteToRole(newRole) {
        // ✅ LOG FAILURE EVENT - UNAUTHORIZED
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    promotedBy.String(),
                Action:     "promote_admin",
                Status:     "failed",
                ErrorCode:  "UNAUTHORIZED",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("unauthorized: cannot promote to %s role", newRole)
    }

    // Old values for audit
    oldRole := admin.AdminRoleLevel

    // Update role level
    if err := s.adminRepo.UpdateAdminRoleLevel(ctx, adminID, newRole, promotedBy); err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    promotedBy.String(),
                Action:     "promote_admin",
                Status:     "failed",
                ErrorCode:  "UPDATE_ROLE_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("failed to promote admin: %w", err)
    }

    // Update permissions based on new role
    newPermissions := s.getPermissionsForRole(newRole)
    if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, newPermissions); err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    promotedBy.String(),
                Action:     "promote_admin",
                Status:     "failed",
                ErrorCode:  "UPDATE_PERMISSIONS_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("failed to update permissions: %w", err)
    }

    // ✅ LOG SUCCESS EVENT
    if s.logProducer != nil {
        event := &models.AdminLogEvent{
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
            AdminID:        adminID.String(),
            AdminRole:      newRole,
            TargetUserID:   adminID.String(),
            Action:         "promote_admin",
            ResourceType:   "admin_user",
            ResourceID:     adminID.String(),
            Status:         "success",
            Changes: map[string]interface{}{
                "old_role": oldRole,
                "new_role": newRole,
            },
            Duration: int64(time.Since(startTime).Milliseconds()),
        }
        _ = s.logProducer.ProduceAdminEvent(ctx, event)
    }

    s.logger.Info("Admin promoted",
        util.String("admin_id", adminID.String()),
        util.String("old_role", oldRole),
        util.String("new_role", newRole),
        util.String("promoted_by", promotedBy.String()),
    )

    return nil
}

// RemoveAdmin removes an admin (soft delete - sets is_active = false)
func (s *AdminService) RemoveAdmin(ctx context.Context, adminID uuid.UUID, removedBy uuid.UUID) error {
    startTime := time.Now()

    // Get admin to remove
    admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    removedBy.String(),
                Action:     "remove_admin",
                Status:     "failed",
                ErrorCode:  "ADMIN_NOT_FOUND",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("admin not found: %w", err)
    }

    // Get remover
    remover, err := s.adminRepo.GetAdminByID(ctx, removedBy)
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    removedBy.String(),
                Action:     "remove_admin",
                Status:     "failed",
                ErrorCode:  "REMOVER_NOT_FOUND",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("remover not found: %w", err)
    }

    // Check permission to remove
    if !remover.CanManageEmployee(admin.AdminRoleLevel) {
        // ✅ LOG FAILURE EVENT - UNAUTHORIZED
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    removedBy.String(),
                Action:     "remove_admin",
                Status:     "failed",
                ErrorCode:  "UNAUTHORIZED",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("unauthorized: cannot remove admin with role %s", admin.AdminRoleLevel)
    }

    // Cannot remove owner
    if admin.IsOwner() {
        // ✅ LOG FAILURE EVENT - CANNOT REMOVE OWNER
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    removedBy.String(),
                Action:     "remove_admin",
                Status:     "failed",
                ErrorCode:  "CANNOT_REMOVE_OWNER",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("cannot remove owner admin")
    }

    // Soft delete
    if err := s.adminRepo.RemoveAdmin(ctx, adminID, removedBy); err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    removedBy.String(),
                Action:     "remove_admin",
                Status:     "failed",
                ErrorCode:  "REMOVE_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("failed to remove admin: %w", err)
    }

    // ✅ LOG SUCCESS EVENT
    if s.logProducer != nil {
        event := &models.AdminLogEvent{
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
            AdminID:        adminID.String(),
            AdminRole:      admin.AdminRoleLevel,
            TargetUserID:   adminID.String(),
            Action:         "remove_admin",
            ResourceType:   "admin_user",
            ResourceID:     adminID.String(),
            Status:         "success",
            Duration:       int64(time.Since(startTime).Milliseconds()),
        }
        _ = s.logProducer.ProduceAdminEvent(ctx, event)
    }

    s.logger.Info("Admin removed",
        util.String("admin_id", adminID.String()),
        util.String("removed_by", removedBy.String()),
    )

    return nil
}

// DeactivateAdmin deactivates an admin (temporary suspend)
func (s *AdminService) DeactivateAdmin(ctx context.Context, adminID uuid.UUID, deactivatedBy uuid.UUID) error {
    startTime := time.Now()

    admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    deactivatedBy.String(),
                Action:     "deactivate_admin",
                Status:     "failed",
                ErrorCode:  "ADMIN_NOT_FOUND",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("admin not found: %w", err)
    }

    if !admin.IsActive {
        // ✅ LOG FAILURE EVENT - ALREADY INACTIVE
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    deactivatedBy.String(),
                Action:     "deactivate_admin",
                Status:     "failed",
                ErrorCode:  "ALREADY_INACTIVE",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("admin is already inactive")
    }

    // Cannot deactivate owner
    if admin.IsOwner() {
        // ✅ LOG FAILURE EVENT - CANNOT DEACTIVATE OWNER
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    deactivatedBy.String(),
                Action:     "deactivate_admin",
                Status:     "failed",
                ErrorCode:  "CANNOT_DEACTIVATE_OWNER",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("cannot deactivate owner admin")
    }

    if err := s.adminRepo.DeactivateAdmin(ctx, adminID); err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    deactivatedBy.String(),
                Action:     "deactivate_admin",
                Status:     "failed",
                ErrorCode:  "DEACTIVATE_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("failed to deactivate admin: %w", err)
    }

    // ✅ LOG SUCCESS EVENT
    if s.logProducer != nil {
        event := &models.AdminLogEvent{
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
            AdminID:        adminID.String(),
            AdminRole:      admin.AdminRoleLevel,
            TargetUserID:   adminID.String(),
            Action:         "deactivate_admin",
            ResourceType:   "admin_user",
            ResourceID:     adminID.String(),
            Status:         "success",
            Duration:       int64(time.Since(startTime).Milliseconds()),
        }
        _ = s.logProducer.ProduceAdminEvent(ctx, event)
    }

    s.logger.Info("Admin deactivated",
        util.String("admin_id", adminID.String()),
    )

    return nil
}

// ActivateAdmin reactivates a deactivated admin
func (s *AdminService) ActivateAdmin(ctx context.Context, adminID uuid.UUID, activatedBy uuid.UUID) error {
    startTime := time.Now()

    admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    activatedBy.String(),
                Action:     "activate_admin",
                Status:     "failed",
                ErrorCode:  "ADMIN_NOT_FOUND",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("admin not found: %w", err)
    }

    if admin.IsActive {
        // ✅ LOG FAILURE EVENT - ALREADY ACTIVE
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    activatedBy.String(),
                Action:     "activate_admin",
                Status:     "failed",
                ErrorCode:  "ALREADY_ACTIVE",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("admin is already active")
    }

    if err := s.adminRepo.ActivateAdmin(ctx, adminID); err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    activatedBy.String(),
                Action:     "activate_admin",
                Status:     "failed",
                ErrorCode:  "ACTIVATE_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("failed to activate admin: %w", err)
    }

    // ✅ LOG SUCCESS EVENT
    if s.logProducer != nil {
        event := &models.AdminLogEvent{
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
            AdminID:        adminID.String(),
            AdminRole:      admin.AdminRoleLevel,
            TargetUserID:   adminID.String(),
            Action:         "activate_admin",
            ResourceType:   "admin_user",
            ResourceID:     adminID.String(),
            Status:         "success",
            Duration:       int64(time.Since(startTime).Milliseconds()),
        }
        _ = s.logProducer.ProduceAdminEvent(ctx, event)
    }

    s.logger.Info("Admin activated",
        util.String("admin_id", adminID.String()),
    )

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

    // Get admin
    admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    updatedBy.String(),
                Action:     "update_admin_permissions",
                Status:     "failed",
                ErrorCode:  "ADMIN_NOT_FOUND",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("admin not found: %w", err)
    }

    // Get updater
    updater, err := s.adminRepo.GetAdminByID(ctx, updatedBy)
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    updatedBy.String(),
                Action:     "update_admin_permissions",
                Status:     "failed",
                ErrorCode:  "UPDATER_NOT_FOUND",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("updater not found: %w", err)
    }

    // Check permission
    if !updater.CanManageEmployee(admin.AdminRoleLevel) {
        // ✅ LOG FAILURE EVENT - UNAUTHORIZED
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    updatedBy.String(),
                Action:     "update_admin_permissions",
                Status:     "failed",
                ErrorCode:  "UNAUTHORIZED",
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("unauthorized: cannot update permissions for %s role", admin.AdminRoleLevel)
    }

    // ✅ FIXED: Remove unused oldPermissions variable
    oldPermissions := admin.AdminPermissions

    // Update permissions
    if err := s.adminRepo.UpdateAdminPermissions(ctx, adminID, permissions); err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    updatedBy.String(),
                Action:     "update_admin_permissions",
                Status:     "failed",
                ErrorCode:  "UPDATE_PERMISSIONS_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("failed to update permissions: %w", err)
    }

    // ✅ LOG SUCCESS EVENT
    if s.logProducer != nil {
        event := &models.AdminLogEvent{
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
            AdminID:        adminID.String(),
            AdminRole:      admin.AdminRoleLevel,
            TargetUserID:   adminID.String(),
            Action:         "update_admin_permissions",
            ResourceType:   "admin_user",
            ResourceID:     adminID.String(),
            Status:         "success",
            Changes: map[string]interface{}{
                "old_permissions": oldPermissions,
                "new_permissions": permissions,
            },
            Duration: int64(time.Since(startTime).Milliseconds()),
        }
        _ = s.logProducer.ProduceAdminEvent(ctx, event)
    }

    s.logger.Info("Admin permissions updated",
        util.String("admin_id", adminID.String()),
        util.Strings("new_permissions", permissions),
    )

    return nil
}

// RecordAdminLogin records admin login attempt
func (s *AdminService) RecordAdminLogin(ctx context.Context, adminID uuid.UUID) error {
    startTime := time.Now()

    if err := s.adminRepo.UpdateLastLogin(ctx, adminID); err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    adminID.String(),
                Action:     "record_admin_login",
                Status:     "failed",
                ErrorCode:  "RECORD_LOGIN_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return fmt.Errorf("failed to record login: %w", err)
    }

    // ✅ LOG SUCCESS EVENT
    if s.logProducer != nil {
        event := &models.AdminLogEvent{
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
        }
        _ = s.logProducer.ProduceAdminEvent(ctx, event)
    }

    // Reset failed attempts on successful login
    if err := s.adminRepo.ResetFailedLoginAttempts(ctx, adminID); err != nil {
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

    attempts, err := s.adminRepo.IncrementFailedLoginAttempts(ctx, adminID)
    if err != nil {
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    adminID.String(),
                Action:     "record_failed_login",
                Status:     "failed",
                ErrorCode:  "RECORD_FAILED_LOGIN_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return false, 0, fmt.Errorf("failed to increment attempts: %w", err)
    }

    // Lock after 5 failed attempts
    const maxAttempts = 5
    shouldLockout := attempts >= maxAttempts

    if shouldLockout {
        // Deactivate admin temporarily
        if err := s.adminRepo.DeactivateAdmin(ctx, adminID); err != nil {
            s.logger.Warn("Failed to deactivate admin after lockout",
                util.String("admin_id", adminID.String()),
                util.ErrorField(err),
            )
            // ✅ LOG FAILURE EVENT FOR LOCKOUT
            if s.logProducer != nil {
                event := &models.AdminLogEvent{
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
                    AdminID:    adminID.String(),
                    Action:     "admin_lockout",
                    Status:     "failed",
                    ErrorCode:  "DEACTIVATE_AFTER_LOCKOUT_FAILED",
                    ErrorMessage: err.Error(),
                    Duration:   int64(time.Since(startTime).Milliseconds()),
                }
                _ = s.logProducer.ProduceAdminEvent(ctx, event)
            }
        } else {
            // ✅ LOG SUCCESS EVENT FOR LOCKOUT
            if s.logProducer != nil {
                event := &models.AdminLogEvent{
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
                }
                _ = s.logProducer.ProduceAdminEvent(ctx, event)
            }
        }
    }

    // ✅ LOG FAILED LOGIN ATTEMPT
    if s.logProducer != nil {
        event := &models.AdminLogEvent{
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
        }
        _ = s.logProducer.ProduceAdminEvent(ctx, event)
    }

    return shouldLockout, attempts, nil
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
    case models.RoleLevelOwner:
        return s.getOwnerPermissions()

    case models.RoleLevelSuperEmployee:
        return []string{
            models.PermissionReadUsers,
            models.PermissionWriteUsers,
            models.PermissionBanUsers,
            models.PermissionUnbanUsers,
            models.PermissionVerifyKYC,
            models.PermissionManageAdmins,
            models.PermissionViewAuditLog,
        }

    case models.RoleLevelEmployee:
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

// HealthCheck verifies admin service health
func (s *AdminService) HealthCheck(ctx context.Context) error {
    return s.adminRepo.HealthCheck(ctx)
}

// GetStats returns admin service statistics
func (s *AdminService) GetStats(ctx context.Context) (map[string]interface{}, error) {
    return s.adminRepo.GetRepositoryStats(ctx)
}

// ✅ FIXED: AuthenticateAdminWithSession - Only checks admin table
func (s *AdminService) AuthenticateAdminWithSession(ctx context.Context, phone string, deviceID string, ipAddress string) (*models.AdminUser, string, error) {
    startTime := time.Now()

    // 1. Authenticate admin (checks only admin_users table)
    admin, err := s.AuthenticateAdmin(ctx, phone)
    if err != nil {
        return nil, "", err
    }

    // 2. Create admin session
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
        // ✅ LOG FAILURE EVENT
        if s.logProducer != nil {
            event := &models.AdminLogEvent{
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
                AdminID:    admin.AdminID.String(),
                Action:     "authenticate_admin_with_session",
                Status:     "failed",
                ErrorCode:  "CREATE_SESSION_FAILED",
                ErrorMessage: err.Error(),
                Duration:   int64(time.Since(startTime).Milliseconds()),
            }
            _ = s.logProducer.ProduceAdminEvent(ctx, event)
        }
        return nil, "", fmt.Errorf("failed to create admin session: %w", err)
    }

    // 3. Update last login
    if err := s.adminRepo.UpdateLastLogin(ctx, admin.AdminID); err != nil {
        s.logger.Warn("Failed to update last login",
            util.String("admin_id", admin.AdminID.String()),
            util.ErrorField(err),
        )
    }

    // ✅ LOG SUCCESS EVENT
    if s.logProducer != nil {
        event := &models.AdminLogEvent{
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
        }
        _ = s.logProducer.ProduceAdminEvent(ctx, event)
    }

    // 5. Return both admin and session token
    return admin, session.SessionToken, nil
}
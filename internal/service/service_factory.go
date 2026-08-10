package service

import (
	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/repository/postgres"
)

// ServiceFactory creates and manages service instances.
type ServiceFactory struct {
	userRepo         postgres.UserRepository
	hasher           *hashing.Hasher
	encryptionMgr    *encryption.EncryptionManager
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	userService      *UserService
}

// NewServiceFactory creates a new service factory.
func NewServiceFactory(
	userRepo postgres.UserRepository,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
) *ServiceFactory {
	return &ServiceFactory{
		userRepo:         userRepo,
		hasher:           hasher,
		encryptionMgr:    encryptionMgr,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
	}
}

// UserService returns the user service instance (singleton).
func (f *ServiceFactory) UserService() *UserService {
	if f.userService == nil {
		f.userService = NewUserService(
			f.userRepo,
			f.hasher,
			f.encryptionMgr,
			f.auditService,
			f.idempotencyStore,
		)
	}
	return f.userService
}

// Cleanup cleans up all services.
func (f *ServiceFactory) Cleanup() {
	if f.userService != nil {
		f.userService.Cleanup()
	}
}

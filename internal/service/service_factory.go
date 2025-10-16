package service

import (
	"auth-service/internal/bucketing"
	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/repository/scylla"

	"go.uber.org/zap"
)

// ServiceFactory creates and manages service instances
type ServiceFactory struct {
	userRepo      scylla.UserRepository
	hasher        *hashing.Hasher
	encryptionMgr *encryption.EncryptionManager
	bucketingMgr  *bucketing.BucketingManager
	logger        *zap.Logger
	userService   *UserService
}

// NewServiceFactory creates a new service factory
func NewServiceFactory(
	userRepo scylla.UserRepository,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	bucketingMgr *bucketing.BucketingManager,
	logger *zap.Logger,
) *ServiceFactory {
	return &ServiceFactory{
		userRepo:      userRepo,
		hasher:        hasher,
		encryptionMgr: encryptionMgr,
		bucketingMgr:  bucketingMgr,
		logger:        logger,
	}
}

// UserService returns the user service instance (singleton)
func (f *ServiceFactory) UserService() *UserService {
	if f.userService == nil {
		f.userService = NewUserService(
			f.userRepo,
			f.hasher,
			f.encryptionMgr,
			f.bucketingMgr,
			f.logger,
		)
	}
	return f.userService
}

// Cleanup cleans up all services
func (f *ServiceFactory) Cleanup() {
	if f.userService != nil {
		f.userService.Cleanup()
	}
}

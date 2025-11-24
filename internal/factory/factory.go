// File: internal/factory/factory.go
// ✅ UPDATED: Complete implementation with bitmask permissions and JWT hybrid tokens

package factory

import (
	"auth-service/internal/bucketing"
	"auth-service/internal/client"
	"auth-service/internal/config"
	"auth-service/internal/consumer"
	"auth-service/internal/encryption"
	"auth-service/internal/handler"
	"auth-service/internal/hashing"
	"auth-service/internal/hashing/pepperstore"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/repository/redis"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/service"
	"auth-service/internal/tls"
	"auth-service/internal/util"
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

type Factory struct {
	config            *config.Config
	tlsManager        *tls.TLSManager
	redisClient       *client.RedisClient
	scyllaClient      *scylla.ScyllaClient
	kafkaProducer     *client.KafkaProducer
	esClient          *client.ESClient
	clickhouseClient  *client.ClickHouseClient
	hasher            *hashing.Hasher
	encryptionManager *encryption.EncryptionManager
	bucketingManager  *bucketing.BucketingManager

	// ✅ UPDATED: PostgreSQL repositories for User and Company
	postgresClient            *client.PostgresClient
	postgresUserRepository    postgres.UserRepository
	postgresCompanyRepository postgres.CompanyRepository

	serviceFactory *service.ServiceFactory
	// ✅ FIXED: Use concrete types for repositories that need type assertions
	adminDeviceRepo        *scylla.AdminDeviceRepositoryImpl
	adminDeviceTrustRepo   scylla.AdminDeviceTrustRepository
	adminMPINRepo          *scylla.AdminMPINRepositoryImpl
	adminDeviceHistoryRepo *scylla.AdminDeviceHistoryRepositoryImpl

	companyService     *service.CompanyService
	adminDeviceService *service.AdminDeviceService
	adminMPINService   *service.AdminMPINService
	userService        *service.UserService
	once               sync.Once
	closeOnce          sync.Once
	closed             chan struct{}
	mpinRepository     scylla.MPINRepository
	mpinService        *service.MPINService
	pepperStoreRepo    pepperstore.PepperStore
	deviceTrustRepo    scylla.DeviceTrustRepository
	otpRepository      scylla.OTPRepository
	otpService         *service.OTPService
	sessionRepo        redis.SessionRepository
	sessionService     *service.SessionService
	deviceRepository   scylla.DeviceRepository
	deviceService      *service.DeviceService
	deviceHistoryRepo  *scylla.DeviceHistoryRepositoryImpl
	kafkaLoggingMgr    *KafkaLoggingManager
	adminRepository    scylla.AdminRepository
	adminService       *service.AdminService

	// ✅ NEW: JWT and RBAC services
	jwtService      *service.JWTService
	rbacInitService *service.RBACInitService
	authHandler     *handler.AuthHandler
	router          chi.Router

	logger *zap.Logger
}

// ============================================================================
// KAFKA LOGGING MANAGER
// ============================================================================

type KafkaLoggingManager struct {
	producer   *service.LogProducerService
	esConsumer *consumer.ESConsumer
	chConsumer *consumer.ClickHouseConsumer
	cancelCtx  context.CancelFunc
	wg         sync.WaitGroup
	logger     *zap.Logger
}

func (m *KafkaLoggingManager) Shutdown() error {
	if m == nil {
		return nil
	}

	m.logger.Info("Shutting down Kafka logging manager...")

	if m.cancelCtx != nil {
		m.cancelCtx()
	}

	m.wg.Wait()

	if m.producer != nil {
		if err := m.producer.Close(); err != nil {
			m.logger.Error("Failed to close log producer", zap.Error(err))
		}
	}

	m.logger.Info("Kafka logging manager shut down successfully")
	return nil
}

func (m *KafkaLoggingManager) GetLogProducerService() *service.LogProducerService {
	return m.producer
}

func (m *KafkaLoggingManager) HealthCheck(ctx context.Context) map[string]error {
	errs := make(map[string]error)

	if m == nil {
		errs["kafka_logging_manager"] = fmt.Errorf("kafka logging manager not initialized")
		return errs
	}

	if m.producer == nil {
		errs["kafka_producer"] = fmt.Errorf("kafka producer not initialized")
	}

	if m.esConsumer != nil {
		if err := m.esConsumer.Health(ctx); err != nil {
			errs["es_consumer"] = err
		}
	}

	if m.chConsumer != nil {
		if err := m.chConsumer.Health(ctx); err != nil {
			errs["clickhouse_consumer"] = err
		}
	}

	return errs
}

// ============================================================================
// FACTORY INITIALIZATION
// ============================================================================
func NewFactory() (*Factory, error) {
	cfg := config.LoadConfig()
	util.Init(cfg.Environment, cfg.Logging.Level, cfg.Logging.Format)
	logger := util.Get()

	f := &Factory{
		config: cfg,
		closed: make(chan struct{}),
		logger: logger,
	}
	if cfg.Server.EnableTLS {
		tlsConfig := &tls.TLSConfig{
			EnableTLS: cfg.Server.EnableTLS,
			CertFile:  cfg.Server.CertFile,
			KeyFile:   cfg.Server.KeyFile,
		}
		f.tlsManager = tls.NewTLSManager(tlsConfig)
	}

	if err := f.initializeClients(); err != nil {
		return nil, fmt.Errorf("failed to initialize clients: %w", err)
	}
	f.initializeManagers()

	kafkaLoggingMgr, err := f.InitializeKafkaLogging()
	if err != nil {
		logger.Error("failed to initialize Kafka logging", zap.Error(err))
	}
	f.kafkaLoggingMgr = kafkaLoggingMgr

	// ✅ ADD THIS: Initialize RBAC permission registry
	ctx := context.Background()
	if err := f.InitializeRBAC(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize RBAC permission registry: %w", err)
	}

	util.Info("Factory initialized successfully",
		util.String("environment", cfg.Environment),
		util.Bool("tls_enabled", cfg.Server.EnableTLS),
		util.Bool("kms_enabled", cfg.KMS.Enabled),
		util.Bool("kafka_logging_enabled", f.kafkaLoggingMgr != nil),
		util.Bool("rbac_initialized", true), // ✅ ADD THIS
	)

	return f, nil
}

// ============================================================================
// KAFKA LOGGING INITIALIZATION - OPTIMIZED EVENT DISTRIBUTION
// ============================================================================

func (f *Factory) InitializeKafkaLogging() (*KafkaLoggingManager, error) {
	logger := util.Get()

	if len(f.config.Kafka.Brokers) == 0 {
		logger.Warn("Kafka brokers not configured, logging to stdout only")
		return nil, nil
	}

	kafkaProducer, err := client.NewKafkaProducer(f.config, logger)
	if err != nil {
		logger.Error("failed to initialize Kafka producer", zap.Error(err))
		return nil, err
	}

	logProducer := service.NewLogProducerService(
		kafkaProducer,
		f.config.Environment,
		"v1.0.0",
	)

	consumerCtx, cancel := context.WithCancel(context.Background())

	mgr := &KafkaLoggingManager{
		producer:  logProducer,
		cancelCtx: cancel,
		logger:    logger,
	}

	// ✅ ELASTICSEARCH CONSUMER - Search & Analytics Events (MULTI-TOPIC)
	if f.config.Elasticsearch.URL != "" && f.esClient != nil {
		esTopics := []string{
			"admin-events",    // Audit trails, role searches
			"user-events",     // User behavior analysis
			"security-events", // Fraud investigation (dual-purpose)
			"session-events",  // Session analytics
		}

		// Create multiple Kafka consumers for ES (one per topic)
		esConsumers := make(map[string]*client.KafkaConsumer)

		for _, topic := range esTopics {
			kafkaConsumer, err := client.NewKafkaConsumer(
				f.config,
				topic,
				"es-consumer-group",
				logger,
			)
			if err != nil {
				logger.Error("failed to create Elasticsearch Kafka consumer",
					zap.String("topic", topic),
					zap.Error(err))
				continue
			}
			esConsumers[topic] = kafkaConsumer
		}

		if len(esConsumers) > 0 {
			esConsumer, err := consumer.NewESConsumer(
				esConsumers,
				f.esClient.Client,
			)
			if err != nil {
				logger.Error("failed to create Elasticsearch consumer", zap.Error(err))
			} else {
				mgr.esConsumer = esConsumer
				mgr.wg.Add(1)
				go func() {
					defer mgr.wg.Done()
					if err := esConsumer.Start(consumerCtx); err != nil {
						logger.Error("ES consumer error", zap.Error(err))
					}
				}()
				logger.Info("Elasticsearch multi-topic consumer started for search events",
					zap.Int("topic_count", len(esConsumers)),
					zap.Strings("topics", esTopics))
			}
		}
	}

	// ✅ CLICKHOUSE CONSUMER - Time-Series & Metrics Events (MULTI-TOPIC)
	if f.config.Clickhouse.URL != "" && f.clickhouseClient != nil {
		chTopics := []string{
			"device-events",   // Device metrics, binding trends
			"mpin-events",     // Authentication patterns
			"otp-events",      // Delivery metrics
			"security-events", // Real-time fraud detection (dual-purpose)
		}

		// Create multiple Kafka consumers for ClickHouse (one per topic)
		chConsumers := make(map[string]*client.KafkaConsumer)

		for _, topic := range chTopics {
			kafkaConsumer, err := client.NewKafkaConsumer(
				f.config,
				topic,
				"clickhouse-consumer-group",
				logger,
			)
			if err != nil {
				logger.Error("failed to create ClickHouse Kafka consumer",
					zap.String("topic", topic),
					zap.Error(err))
				continue
			}
			chConsumers[topic] = kafkaConsumer
		}

		if len(chConsumers) > 0 {
			chConsumer := consumer.NewClickHouseConsumer(
				chConsumers,
				f.clickhouseClient.Conn(),
				1000,          // batch size
				5*time.Second, // flush interval
			)
			mgr.chConsumer = chConsumer
			mgr.wg.Add(1)
			go func() {
				defer mgr.wg.Done()
				if err := chConsumer.Start(consumerCtx); err != nil {
					logger.Error("ClickHouse consumer error", zap.Error(err))
				}
			}()
			logger.Info("ClickHouse multi-topic consumer started for time-series events",
				zap.Int("topic_count", len(chConsumers)),
				zap.Strings("topics", chTopics))
		}
	}

	logger.Info("Kafka logging system initialized with optimized event distribution",
		zap.Bool("es_enabled", mgr.esConsumer != nil),
		zap.Bool("ch_enabled", mgr.chConsumer != nil),
	)

	return mgr, nil
}

// ============================================================================
// ADMIN REPOSITORY GETTERS - FIXED
// ============================================================================

func (f *Factory) AdminDeviceRepository() *scylla.AdminDeviceRepositoryImpl {
	if f.adminDeviceRepo == nil {
		f.adminDeviceRepo = scylla.NewAdminDeviceRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.adminDeviceRepo
}

func (f *Factory) AdminDeviceTrustRepository() scylla.AdminDeviceTrustRepository {
	if f.adminDeviceTrustRepo == nil {
		f.adminDeviceTrustRepo = scylla.NewAdminDeviceTrustRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.adminDeviceTrustRepo
}

func (f *Factory) AdminMPINRepository() *scylla.AdminMPINRepositoryImpl {
	if f.adminMPINRepo == nil {
		f.adminMPINRepo = scylla.NewAdminMPINRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.adminMPINRepo
}

func (f *Factory) AdminDeviceHistoryRepository() *scylla.AdminDeviceHistoryRepositoryImpl {
	if f.adminDeviceHistoryRepo == nil {
		f.adminDeviceHistoryRepo = scylla.NewAdminDeviceHistoryRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.adminDeviceHistoryRepo
}

// ============================================================================
// ✅ UPDATED REPOSITORY GETTERS - POSTGRESQL MIGRATION
// ============================================================================

func (f *Factory) CompanyRepository() postgres.CompanyRepository {
	if f.postgresCompanyRepository == nil {
		f.postgresCompanyRepository = postgres.NewCompanyRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.postgresCompanyRepository
}

func (f *Factory) PepperStoreRepository() pepperstore.PepperStore {
	if f.pepperStoreRepo == nil {
		f.pepperStoreRepo = scylla.NewPepperStoreRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.pepperStoreRepo
}

func (f *Factory) UserRepository() postgres.UserRepository {
	if f.postgresUserRepository == nil {
		f.postgresUserRepository = postgres.NewUserRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.postgresUserRepository
}

func (f *Factory) OTPRepository() scylla.OTPRepository {
	if f.otpRepository == nil {
		f.otpRepository = scylla.NewOTPRepository(
			f.ScyllaClient(),
			f.Hasher(),
			f.BucketingManager(),
			f.logger,
		)
	}
	return f.otpRepository
}

func (f *Factory) MPINRepository() scylla.MPINRepository {
	if f.mpinRepository == nil {
		f.mpinRepository = scylla.NewMPINRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.mpinRepository
}

func (f *Factory) GetDeviceTrustRepository() scylla.DeviceTrustRepository {
	if f.deviceTrustRepo == nil {
		f.deviceTrustRepo = scylla.NewDeviceTrustRepository(f.scyllaClient, f.logger)
	}
	return f.deviceTrustRepo
}

func (f *Factory) SessionRepository() redis.SessionRepository {
	if f.sessionRepo == nil {
		f.sessionRepo = redis.NewSessionRepository(
			f.redisClient.Client(),
			f.logger,
		)
	}
	return f.sessionRepo
}

func (f *Factory) DeviceRepository() scylla.DeviceRepository {
	if f.deviceRepository == nil {
		f.deviceRepository = scylla.NewDeviceRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.deviceRepository
}

func (f *Factory) GetDeviceHistoryRepository() *scylla.DeviceHistoryRepositoryImpl {
	if f.deviceHistoryRepo == nil {
		f.deviceHistoryRepo = scylla.NewDeviceHistoryRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.deviceHistoryRepo
}

func (f *Factory) AdminRepository() scylla.AdminRepository {
	if f.adminRepository == nil {
		f.adminRepository = scylla.NewAdminRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.adminRepository
}

// ============================================================================
// ✅ JWT AND RBAC SERVICES
// ============================================================================

func (f *Factory) GetJWTService() *service.JWTService {
	if f.jwtService == nil {
		f.jwtService = service.NewJWTService(
			f.Config(),
			f.CompanyRepository(),
			f.logger,
		)
	}
	return f.jwtService
}

func (f *Factory) GetRBACInitService() *service.RBACInitService {
	if f.rbacInitService == nil {
		f.rbacInitService = service.NewRBACInitService(
			f.CompanyRepository(),
			f.logger,
		)
	}
	return f.rbacInitService
}

// ============================================================================
// ✅ SERVICE GETTERS - UPDATED WITH JWT AND BITMASK SUPPORT
// ============================================================================

func (f *Factory) ServiceFactory() *service.ServiceFactory {
	if f.serviceFactory == nil {
		f.serviceFactory = service.NewServiceFactory(
			f.UserRepository(),
			f.Hasher(),
			f.EncryptionManager(),
			f.logger,
		)
	}
	return f.serviceFactory
}

func (f *Factory) GetUserService() *service.UserService {
	f.once.Do(func() {
		repo := f.UserRepository()
		hasher := f.Hasher()
		encMgr := f.EncryptionManager()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		f.userService = service.NewUserServiceWithCache(
			repo, hasher, encMgr, distCache, logger,
		)

		logProducer := f.GetLogProducerService()
		if logProducer != nil {
			f.userService.SetLogProducerService(logProducer)
		}
	})
	return f.userService
}

func (f *Factory) GetOTPService() *service.OTPService {
	if f.otpService == nil {
		repo := f.OTPRepository()
		hasher := f.Hasher()
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		logProducer := f.GetLogProducerService()
		f.otpService = service.NewOTPService(repo, hasher, cfg, distCache, logger, logProducer)
	}
	return f.otpService
}

func (f *Factory) GetMPINService() *service.MPINService {
	if f.mpinService == nil {
		mpinRepo := f.MPINRepository()
		userRepo := f.UserRepository()
		deviceTrustRepo := f.GetDeviceTrustRepository()
		otpService := f.GetOTPService()
		encryptionMgr := f.EncryptionManager()
		hasher := f.Hasher()
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		logProducer := f.GetLogProducerService()
		f.mpinService = service.NewMPINService(
			mpinRepo,
			userRepo,
			deviceTrustRepo,
			otpService,
			encryptionMgr,
			hasher,
			cfg,
			logger,
			logProducer,
		)

		if distCache != nil {
			f.mpinService.SetDistributedCache(distCache)
		}
	}
	return f.mpinService
}

func (f *Factory) GetSessionService() *service.SessionService {
	if f.sessionService == nil {
		sessionRepo := f.SessionRepository()
		cfg := f.Config()
		jwtService := f.GetJWTService()
		logger := f.logger
		logProducer := f.GetLogProducerService()
		companyRepo := f.CompanyRepository()

		f.sessionService = service.NewSessionService(
			sessionRepo,
			cfg,
			jwtService,
			logger,
			logProducer,
			companyRepo,
		)
	}
	return f.sessionService
}

func (f *Factory) GetDeviceService() *service.DeviceService {
	if f.deviceService == nil {
		deviceRepo := f.DeviceRepository()
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		f.deviceService = service.NewDeviceService(
			deviceRepo,
			distCache,
			*cfg,
			logger,
		)

		historyRepo := f.GetDeviceHistoryRepository()
		f.deviceService.SetHistoryRepository(historyRepo)

		logProducer := f.GetLogProducerService()
		if logProducer != nil {
			f.deviceService.SetLogProducerService(logProducer)
		}
	}
	return f.deviceService
}

func (f *Factory) GetCompanyService() *service.CompanyService {
	if f.companyService == nil {
		f.companyService = service.NewCompanyService(
			f.CompanyRepository(),
			f.GetUserService(),
			f.logger,
		)
	}
	return f.companyService
}

// ============================================================================
// ✅ ADMIN SERVICE GETTERS
// ============================================================================

func (f *Factory) GetAdminDeviceService() *service.AdminDeviceService {
	if f.adminDeviceService == nil {
		deviceRepo := f.AdminDeviceRepository()
		trustRepo := f.AdminDeviceTrustRepository()
		mpinRepo := f.AdminMPINRepository()
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		f.adminDeviceService = service.NewAdminDeviceService(
			deviceRepo,
			trustRepo,
			mpinRepo,
			distCache,
			*cfg,
			logger,
		)

		historyRepo := f.AdminDeviceHistoryRepository()
		f.adminDeviceService.SetHistoryRepository(historyRepo)

		logProducer := f.GetLogProducerService()
		if logProducer != nil {
			f.adminDeviceService.SetLogProducerService(logProducer)
		}
	}
	return f.adminDeviceService
}

func (f *Factory) GetAdminMPINService() *service.AdminMPINService {
	if f.adminMPINService == nil {
		mpinRepo := f.AdminMPINRepository()
		adminRepo := f.AdminRepository()
		deviceTrustRepo := f.AdminDeviceTrustRepository()
		otpService := f.GetOTPService()
		encryptionMgr := f.EncryptionManager()
		hasher := f.Hasher()
		cfg := f.Config()
		logger := f.logger

		logProducer := f.GetLogProducerService()

		f.adminMPINService = service.NewAdminMPINService(
			mpinRepo,
			adminRepo,
			deviceTrustRepo,
			otpService,
			encryptionMgr,
			hasher,
			cfg,
			logger,
			logProducer,
		)

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
			f.adminMPINService.SetDistributedCache(distCache)
		}
	}
	return f.adminMPINService
}

func (f *Factory) GetAdminService() *service.AdminService {
	if f.adminService == nil {
		f.adminService = service.NewAdminService(
			f.AdminRepository(),
			f.UserRepository(),
			f.GetSessionService(),
			f.GetOTPService(),
			f.GetMPINService(),
			f.GetDeviceService(),
			f.Hasher(),
			f.EncryptionManager(),
			f.logger,
		)

		logProducer := f.GetLogProducerService()
		if logProducer != nil {
			f.adminService.SetLogProducerService(logProducer)
		}
	}
	return f.adminService
}

// ============================================================================
// ✅ CLIENT INITIALIZATION
// ============================================================================

func (f *Factory) initializeClients() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var initErrors []error

	// Redis
	if rc, err := client.NewRedisClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("redis: %w", err))
	} else {
		f.redisClient = rc
		if err := f.redisClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("redis health check: %w", err))
		} else {
			util.Info("Redis client initialized and healthy")
		}
	}

	// PostgreSQL
	if pgc, err := client.NewPostgresClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("postgres: %w", err))
	} else {
		f.postgresClient = pgc
		if err := f.postgresClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("postgres health check: %w", err))
		} else {
			util.Info("PostgreSQL client initialized and healthy")
		}
	}

	// ScyllaDB
	if sc, err := scylla.NewScyllaClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("scylla: %w", err))
	} else {
		f.scyllaClient = sc
		if err := f.scyllaClient.HealthCheck(); err != nil {
			initErrors = append(initErrors, fmt.Errorf("scylla health check: %w", err))
		} else {
			util.Info("ScyllaDB client initialized and healthy")
		}
	}

	// Kafka
	if kp, err := client.NewKafkaProducer(f.config, f.logger); err != nil {
		util.Warn("Kafka producer initialization failed - proceeding without Kafka", util.ErrorField(err))
	} else {
		f.kafkaProducer = kp
		util.Info("Kafka producer initialized")
	}

	// Elasticsearch
	if ec, err := client.NewElasticsearchClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("elasticsearch: %w", err))
	} else {
		f.esClient = ec
		if err := f.esClient.HealthCheck(); err != nil {
			initErrors = append(initErrors, fmt.Errorf("elasticsearch health check: %w", err))
		} else {
			util.Info("Elasticsearch client initialized and healthy")
		}
	}

	// ClickHouse
	if chc, err := client.NewClickHouseClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("clickhouse: %w", err))
	} else {
		f.clickhouseClient = chc
		if err := f.clickhouseClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("clickhouse health check: %w", err))
		} else {
			util.Info("ClickHouse client initialized and healthy")
		}
	}

	if len(initErrors) > 0 {
		if f.config.IsProduction() {
			return fmt.Errorf("critical service initialization failed: %v", initErrors)
		}
		for _, e := range initErrors {
			util.Warn("Service initialization warning", util.ErrorField(e))
		}
	}
	return nil
}

func (f *Factory) initializeManagers() {
	pepperStore := f.PepperStoreRepository()

	hasher, err := hashing.NewHasher(f.config, pepperStore)
	if err != nil {
		f.logger.Error("CRITICAL: Failed to initialize hasher",
			zap.Error(err),
			zap.String("impact", "MPIN operations will fail"))

		if f.config.IsProduction() {
			panic(fmt.Sprintf("CRITICAL: Failed to initialize hasher: %v", err))
		}

		f.hasher = nil
	} else {
		f.hasher = hasher
		util.Info("Hasher initialized with pepper persistence",
			util.Int("current_pepper_version", hasher.GetCurrentPepperVersion()))
	}

	var kmsClient *kms.Client
	if f.config.KMS.Enabled {
		kmsClient = nil
	}

	f.encryptionManager = encryption.NewEncryptionManager(f.config, kmsClient)
	f.bucketingManager = bucketing.NewBucketingManager(f.config)

	if f.hasher != nil && f.config.IsProduction() {
		f.hasher.StartPepperRotation()
		util.Info("Pepper rotation started")
	}

	util.Info("Managers initialized successfully",
		util.Bool("hashing_initialized", f.hasher != nil),
		util.Bool("encryption_initialized", f.encryptionManager != nil),
		util.Bool("bucketing_initialized", f.bucketingManager != nil),
		util.Bool("pepper_persistence_enabled", f.hasher != nil),
	)
}

// ============================================================================
// ✅ HANDLER INITIALIZATION - UPDATED WITH JWT AND RBAC
// ============================================================================

func (f *Factory) InitializeHandlers() error {
	logger := f.logger

	// Get all services
	userService := f.GetUserService()
	otpService := f.GetOTPService()
	mpinService := f.GetMPINService()
	adminMPINService := f.GetAdminMPINService()
	adminDeviceService := f.GetAdminDeviceService()
	sessionService := f.GetSessionService()
	deviceService := f.GetDeviceService()
	adminService := f.GetAdminService()
	companyService := f.GetCompanyService()
	jwtService := f.GetJWTService()

	// Initialize handlers
	otpHandler := handler.NewOTPHandler(
		otpService,
		sessionService,
		logger,
	)

	adminHandler := handler.NewAdminHandler(
		adminService,
		companyService,
		userService,
		otpService,
		adminMPINService,
		adminDeviceService,
		sessionService,
		jwtService,
		logger,
	)

	rbacHandler := handler.NewRBACHandler(companyService, logger)

	// ✅ FIXED: Auth handler with all required services
	authHandler := handler.NewAuthHandler(
		otpService,
		mpinService,
		sessionService,
		userService,
		companyService,
		deviceService,
		jwtService,
		logger,
	)
	f.authHandler = authHandler

	// ✅ FIXED: Router with correct number of arguments
	f.router = handler.NewRouter(
		otpHandler,
		adminHandler,
		authHandler,
		rbacHandler,
		sessionService,
		jwtService,
		logger,
	)

	logger.Info("Handlers and router initialized with JWT and bitmask support")
	return nil
}

func (f *Factory) GetRouter() chi.Router {
	if f.router == nil {
		if err := f.InitializeHandlers(); err != nil {
			f.logger.Fatal("Failed to initialize handlers", util.ErrorField(err))
		}
	}
	return f.router
}

// ============================================================================
// ✅ RBAC INITIALIZATION
// ============================================================================

func (f *Factory) InitializeRBAC(ctx context.Context) error {
	rbacInitService := f.GetRBACInitService()
	if err := rbacInitService.InitializePermissionRegistry(ctx); err != nil {
		return fmt.Errorf("failed to initialize RBAC permission registry: %w", err)
	}
	f.logger.Info("RBAC permission registry initialized successfully")
	return nil
}

// ============================================================================
// ✅ HEALTH CHECK - UPDATED FOR JWT AND RBAC
// ============================================================================

func (f *Factory) HealthCheck(ctx context.Context) map[string]error {
	errs := make(map[string]error)

	// PostgreSQL health checks
	if f.postgresClient != nil {
		if err := f.postgresClient.HealthCheck(ctx); err != nil {
			errs["postgres"] = err
		}
	} else {
		errs["postgres"] = fmt.Errorf("postgres client not initialized")
	}

	if f.postgresUserRepository != nil {
		if err := f.postgresUserRepository.HealthCheck(ctx); err != nil {
			errs["postgres_user_repository"] = err
		}
	} else {
		errs["postgres_user_repository"] = fmt.Errorf("postgres user repository not initialized")
	}

	if f.postgresCompanyRepository != nil {
		if err := f.postgresCompanyRepository.HealthCheck(ctx); err != nil {
			errs["postgres_company_repository"] = err
		}
	} else {
		errs["postgres_company_repository"] = fmt.Errorf("postgres company repository not initialized")
	}

	// Other clients and repositories...
	if f.redisClient != nil {
		if err := f.redisClient.HealthCheck(ctx); err != nil {
			errs["redis"] = err
		}
	} else {
		errs["redis"] = fmt.Errorf("redis client not initialized")
	}

	if f.mpinRepository != nil {
		if err := f.mpinRepository.HealthCheck(ctx); err != nil {
			errs["mpin_repository"] = err
		}
	} else {
		errs["mpin_repository"] = fmt.Errorf("mpin repository not initialized")
	}

	if f.scyllaClient != nil {
		if err := f.scyllaClient.HealthCheck(); err != nil {
			errs["scylla"] = err
		}
	} else {
		errs["scylla"] = fmt.Errorf("scylla client not initialized")
	}

	if f.esClient != nil {
		if err := f.esClient.HealthCheck(); err != nil {
			errs["elasticsearch"] = err
		}
	} else {
		errs["elasticsearch"] = fmt.Errorf("elasticsearch client not initialized")
	}

	if f.clickhouseClient != nil {
		if err := f.clickhouseClient.HealthCheck(ctx); err != nil {
			errs["clickhouse"] = err
		}
	} else {
		errs["clickhouse"] = fmt.Errorf("clickhouse client not initialized")
	}

	if f.kafkaProducer != nil {
		if err := f.kafkaProducer.HealthCheck(ctx); err != nil {
			errs["kafka"] = err
		}
	}

	if f.encryptionManager == nil {
		errs["encryption"] = fmt.Errorf("encryption manager not initialized")
	}

	if f.bucketingManager == nil {
		errs["bucketing"] = fmt.Errorf("bucketing manager not initialized")
	}

	if f.sessionRepo != nil {
		if err := f.sessionRepo.HealthCheck(ctx); err != nil {
			errs["session_repository"] = err
		}
	} else {
		errs["session_repository"] = fmt.Errorf("session repository not initialized")
	}

	if f.deviceRepository != nil {
		if err := f.deviceRepository.HealthCheck(ctx); err != nil {
			errs["device_repository"] = err
		}
	} else {
		errs["device_repository"] = fmt.Errorf("device repository not initialized")
	}

	if f.deviceHistoryRepo != nil {
		if err := f.deviceHistoryRepo.HealthCheck(ctx); err != nil {
			errs["device_history_repository"] = err
		}
	} else {
		errs["device_history_repository"] = fmt.Errorf("device history repository not initialized")
	}

	if f.adminRepository != nil {
		if err := f.adminRepository.HealthCheck(ctx); err != nil {
			errs["admin_repository"] = err
		}
	} else {
		errs["admin_repository"] = fmt.Errorf("admin repository not initialized")
	}

	// ✅ NEW: JWT and RBAC service health checks
	if f.jwtService != nil {
		// JWT service doesn't have a health check method, but we can verify it's initialized
	} else {
		errs["jwt_service"] = fmt.Errorf("JWT service not initialized")
	}

	if f.rbacInitService != nil {
		// RBAC init service doesn't have a health check method
	} else {
		errs["rbac_init_service"] = fmt.Errorf("RBAC init service not initialized")
	}

	// ✅ NEW: Company service health check
	if f.companyService != nil {
		if err := f.companyService.HealthCheck(ctx); err != nil {
			errs["company_service"] = err
		}
	} else {
		errs["company_service"] = fmt.Errorf("company service not initialized")
	}

	// Kafka logging health check
	if f.kafkaLoggingMgr != nil {
		kafkaErrs := f.kafkaLoggingMgr.HealthCheck(ctx)
		for k, v := range kafkaErrs {
			errs[k] = v
		}
	} else {
		errs["kafka_logging"] = fmt.Errorf("kafka logging manager not initialized")
	}

	// Pepper store health check
	if f.pepperStoreRepo != nil {
		_, _, err := f.pepperStoreRepo.GetCurrentPepper(ctx)
		if err != nil {
			errs["pepper_store"] = fmt.Errorf("pepper store health check failed: %w", err)
		}
	} else {
		errs["pepper_store"] = fmt.Errorf("pepper store repository not initialized")
	}

	// Hasher health check
	if f.hasher != nil {
		if err := f.hasher.HealthCheck(ctx); err != nil {
			errs["hasher"] = err
		}
	} else {
		errs["hasher"] = fmt.Errorf("hasher not initialized")
	}

	// Admin repositories health checks
	if f.adminDeviceRepo != nil {
		if err := f.adminDeviceRepo.HealthCheck(ctx); err != nil {
			errs["admin_device_repository"] = err
		}
	} else {
		errs["admin_device_repository"] = fmt.Errorf("admin device repository not initialized")
	}

	if f.adminMPINRepo != nil {
		if err := f.adminMPINRepo.HealthCheck(ctx); err != nil {
			errs["admin_mpin_repository"] = err
		}
	} else {
		errs["admin_mpin_repository"] = fmt.Errorf("admin MPIN repository not initialized")
	}

	// Admin services health checks
	if f.adminDeviceService != nil {
		if err := f.adminDeviceService.HealthCheck(ctx); err != nil {
			errs["admin_device_service"] = err
		}
	} else {
		errs["admin_device_service"] = fmt.Errorf("admin device service not initialized")
	}

	if f.adminMPINService != nil {
		if err := f.adminMPINService.HealthCheck(ctx); err != nil {
			errs["admin_mpin_service"] = err
		}
	} else {
		errs["admin_mpin_service"] = fmt.Errorf("admin MPIN service not initialized")
	}

	return errs
}

// ============================================================================
// ✅ CLEANUP
// ============================================================================

func (f *Factory) Close() error {
	f.closeOnce.Do(func() {
		close(f.closed)
		util.Info("Shutting down factory...")

		// Shutdown Kafka logging first
		if f.kafkaLoggingMgr != nil {
			if err := f.kafkaLoggingMgr.Shutdown(); err != nil {
				util.Error("Failed to shutdown Kafka logging", util.ErrorField(err))
			}
			util.Info("Kafka logging system shut down")
		}

		// PostgreSQL cleanup
		if f.postgresClient != nil {
			f.postgresClient.Close()
			util.Info("PostgreSQL client closed")
		}

		if f.clickhouseClient != nil {
			f.clickhouseClient.Close()
			util.Info("ClickHouse client closed")
		}

		if f.esClient != nil {
			f.esClient.Close()
			util.Info("Elasticsearch client closed")
		}

		if f.kafkaProducer != nil {
			f.kafkaProducer.Close()
			util.Info("Kafka producer closed")
		}

		if f.serviceFactory != nil {
			f.serviceFactory.Cleanup()
			util.Info("Service factory cleaned up")
		}

		if f.scyllaClient != nil {
			f.scyllaClient.Close()
			util.Info("ScyllaDB client closed")
		}

		if f.redisClient != nil {
			f.redisClient.Close()
			util.Info("Redis client closed")
		}

		// Hasher cleanup
		if f.hasher != nil {
			util.Info("Hasher shut down")
		}

		if f.encryptionManager != nil {
			f.encryptionManager.ClearCache()
			util.Info("Encryption manager cache cleared")
		}

		util.Sync()
		util.Info("Factory shutdown completed")
	})
	return nil
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return i
}

// ============================================================================
// ✅ SIMPLE GETTERS
// ============================================================================

func (f *Factory) Config() *config.Config                           { return f.config }
func (f *Factory) TLSManager() *tls.TLSManager                      { return f.tlsManager }
func (f *Factory) ScyllaClient() *scylla.ScyllaClient               { return f.scyllaClient }
func (f *Factory) Hasher() *hashing.Hasher                          { return f.hasher }
func (f *Factory) EncryptionManager() *encryption.EncryptionManager { return f.encryptionManager }
func (f *Factory) BucketingManager() *bucketing.BucketingManager    { return f.bucketingManager }
func (f *Factory) PostgresClient() *client.PostgresClient           { return f.postgresClient }
func (f *Factory) GetLogProducerService() *service.LogProducerService {
	if f.kafkaLoggingMgr == nil {
		return nil
	}
	return f.kafkaLoggingMgr.GetLogProducerService()
}

// ✅ UPDATED: PostgreSQL repository getters
func (f *Factory) PostgresUserRepository() postgres.UserRepository {
	if f.postgresUserRepository == nil {
		f.postgresUserRepository = postgres.NewUserRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.postgresUserRepository
}

func (f *Factory) PostgresCompanyRepository() postgres.CompanyRepository {
	if f.postgresCompanyRepository == nil {
		f.postgresCompanyRepository = postgres.NewCompanyRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.postgresCompanyRepository
}

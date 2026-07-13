package factory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting"
	"auth-service/internal/attendance/service/usage_integration"
	"auth-service/internal/bucketing"
	"auth-service/internal/client"
	"auth-service/internal/config"
	"auth-service/internal/consumer"
	"auth-service/internal/email"
	"auth-service/internal/encryption"
	"auth-service/internal/handler"
	"auth-service/internal/hashing"
	"auth-service/internal/hashing/pepperstore"
	hrhandler "auth-service/internal/hr/handler"
	leavehandler "auth-service/internal/hr/leave/handler"
	leaverepo "auth-service/internal/hr/leave/repository"
	leavesvc "auth-service/internal/hr/leave/service"
	payrollhandler "auth-service/internal/hr/payroll/handler"
	payrollrepo "auth-service/internal/hr/payroll/repository"
	payrollsvc "auth-service/internal/hr/payroll/service"
	"auth-service/internal/hr/payroll/service/pdf"
	hrpostgres "auth-service/internal/hr/repository"
	hrservice "auth-service/internal/hr/service"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	"auth-service/internal/inventory"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/repository/redis"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/sales"
	salesRepo "auth-service/internal/sales/repository"
	"auth-service/internal/service"
	"auth-service/internal/sms"
	"auth-service/internal/subscription"
	subRepo "auth-service/internal/subscription/repository"
	"auth-service/internal/tls"
	"auth-service/internal/util"
)

type Factory struct {
	config                       *config.Config
	tlsManager                   *tls.TLSManager
	redisClient                  *client.RedisClient
	scyllaClient                 *scylla.ScyllaClient
	kafkaProducer                *client.KafkaProducer
	esClient                     *client.ESClient
	clickhouseClient             *client.ClickHouseClient
	hasher                       *hashing.Hasher
	encryptionManager            *encryption.EncryptionManager
	bucketingManager             *bucketing.BucketingManager
	pairingRepo                  redis.PairingRepository
	pairingService               *service.PairingService
	wsService                    *service.WebSocketService
	pairingHandler               *handler.PairingHandler
	wsHandler                    *handler.WebSocketHandler
	qrUtil                       *util.QRUtil
	hmacUtil                     *util.HMACUtil
	hrEmployeeRepository         hrpostgres.EmployeeRepository
	orgUnitRepository            hrpostgres.OrgUnitRepository
	leaveRepository              leaverepo.LeaveRepository
	payrollRepository            payrollrepo.PayrollRepository
	compensationRepo             payrollrepo.CompensationRepository
	salaryStructureRepo          payrollrepo.SalaryStructureRepository
	statutoryProfileRepo         payrollrepo.StatutoryProfileRepository
	statutoryRepo                payrollrepo.StatutoryRepository
	componentRepo                payrollrepo.ComponentRepository
	companySettingsRepo          payrollrepo.CompanySettingsRepository
	arrearsRepo                  payrollrepo.ArrearsRepository
	loanRepo                     payrollrepo.LoanRepository
	bankDetailsRepo              payrollrepo.BankDetailsRepository
	payslipRepo                  payrollrepo.PayslipRepository
	taxDeclarationRepo           payrollrepo.TaxDeclarationRepository
	arrearsSvc                   payrollsvc.ArrearsService
	pdfGenerator                 payrollsvc.PDFGenerator
	orgUnitHandler               *hrhandler.OrgUnitHandler
	hrAuditHandler               *audit.AuditHandler
	hrEmployeeHandler            *hrhandler.EmployeeHandler
	leaveAdminHandler            *leavehandler.LeaveAdminHandler
	leaveQueryHandler            *leavehandler.LeaveQueryHandler
	leaveRequestHandler          *leavehandler.LeaveRequestHandler
	orgUnitService               *hrservice.OrgUnitService
	orgUnitQueryService          *hrservice.OrgUnitQueryService
	auditService                 *audit.AuditService
	auditQueryService            *audit.AuditQueryService
	auditRepository              audit.AuditRepository
	employeeQueryService         *hrservice.EmployeeQueryService
	employeeService              *hrservice.EmployeeService
	leaveBalanceService          leavesvc.LeaveBalanceService
	leavePolicyService           leavesvc.LeavePolicyService
	leaveAccrualService          leavesvc.LeaveAccrualService
	leaveQueryService            leavesvc.LeaveQueryService
	leaveRequestService          leavesvc.LeaveRequestService
	documentStorage              hrservice.DocumentStorage
	postgresClient               *client.PostgresClient
	postgresUserRepository       postgres.UserRepository
	postgresCompanyRepository    postgres.CompanyRepository
	smsManager                   *sms.SMSManager
	serviceFactory               *service.ServiceFactory
	adminDeviceRepo              *scylla.AdminDeviceRepositoryImpl
	adminDeviceTrustRepo         scylla.AdminDeviceTrustRepository
	adminMPINRepo                *scylla.AdminMPINRepositoryImpl
	adminDeviceHistoryRepo       *scylla.AdminDeviceHistoryRepositoryImpl
	userOTPService               *service.UserOTPService
	companyService               *service.CompanyService
	adminDeviceService           *service.AdminDeviceService
	adminMPINService             *service.AdminMPINService
	userService                  *service.UserService
	mpinRepository               scylla.MPINRepository
	mpinService                  *service.MPINService
	pepperStoreRepo              pepperstore.PepperStore
	deviceTrustRepo              scylla.DeviceTrustRepository
	otpRepository                scylla.OTPRepository
	otpService                   *service.OTPService
	sessionRepo                  redis.SessionRepository
	sessionService               *service.SessionService
	deviceRepository             scylla.DeviceRepository
	deviceService                *service.DeviceService
	deviceHistoryRepo            *scylla.DeviceHistoryRepositoryImpl
	kafkaLoggingMgr              *KafkaLoggingManager
	adminRepository              postgres.AdminRepository
	adminService                 *service.AdminService
	jwtService                   *service.JWTService
	rbacInitService              *service.RBACInitService
	authHandler                  *handler.AuthHandler
	router                       chi.Router
	logger                       *zap.Logger
	auditOutboxService           *audit.AuditOutboxService
	auditOutboxCancel            context.CancelFunc
	once                         sync.Once
	closeOnce                    sync.Once
	closed                       chan struct{}
	leavePolicyResolutionService leavesvc.LeavePolicyResolutionService
	leavePolicyResolutionHandler *leavehandler.LeavePolicyResolutionHandler
	leavePolicyConfigService     leavesvc.LeavePolicyConfigService
	compensationSvc              payrollsvc.CompensationService
	payrollAdjustmentSvc         payrollsvc.PayrollAdjustmentService
	payrollLockSvc               payrollsvc.PayrollLockService
	payrollEngineSvc             payrollsvc.PayrollEngineService
	payrollQuerySvc              payrollsvc.PayrollQueryService
	salaryStructureSvc           payrollsvc.SalaryStructureService
	statutoryProfileSvc          payrollsvc.StatutoryProfileService
	statutoryEngineSvc           payrollsvc.StatutoryEngine
	compensationHandler          *payrollhandler.CompensationHandler
	payrollAdjustmentHandler     *payrollhandler.PayrollAdjustmentHandler
	payrollLockHandler           *payrollhandler.PayrollLockHandler
	payrollCommandHandler        *payrollhandler.PayrollCommandHandler
	payrollQueryHandler          *payrollhandler.PayrollQueryHandler
	payrollRunHandler            *payrollhandler.PayrollRunHandler
	salaryStructureHandler       *payrollhandler.SalaryStructureHandler
	statutoryProfileHandler      *payrollhandler.StatutoryProfileHandler
	attendanceRuleRepo           payrollrepo.AttendanceRuleRepository
	attendanceRuleSvc            payrollsvc.AttendanceRuleService
	attendanceRuleHandler        *payrollhandler.AttendanceRuleHandler
	employeeFineRepo             payrollrepo.EmployeeFineRepository
	employeeFineSvc              payrollsvc.EmployeeFineService
	employeeFineHandler          *payrollhandler.EmployeeFineHandler
	payrollJobRepo               payrollrepo.PayrollJobRepository
	payrollWorker                *payrollsvc.PayrollWorker
	payrollWorkerCancel          context.CancelFunc
	bankExportSvc                payrollsvc.BankExportService
	componentSvc                 payrollsvc.ComponentService
	loanSvc                      payrollsvc.LoanService
	payslipSvc                   payrollsvc.PayslipService
	reportingSvc                 payrollsvc.ReportingService
	taxDeclarationSvc            payrollsvc.TaxDeclarationService
	bankExportHandler            *payrollhandler.BankExportHandler
	componentHandler             *payrollhandler.ComponentHandler
	loanHandler                  *payrollhandler.LoanHandler
	payslipHandler               *payrollhandler.PayslipHandler
	reportingHandler             *payrollhandler.ReportingHandler
	taxDeclarationHandler        *payrollhandler.TaxDeclarationHandler
	academicsInfra               *AcademicsInfraFactory
	accountingInfra              *AccountingInfraFactory
	analyticsConsumer            *consumer.AnalyticsConsumer
	analyticsConsumerCancel      context.CancelFunc
	inventoryInfra               *InventoryInfraFactory
	studentConsumer              *consumer.StudentConsumer
	studentConsumerCancel        context.CancelFunc
	accountingConsumer           *consumer.AccountingConsumer
	accountingConsumerCancel     context.CancelFunc
	inventoryConsumer            *consumer.InventoryConsumer
	inventoryConsumerCancel      context.CancelFunc
	salesInfra                   *SalesInfraFactory
	subscriptionInfra            *SubscriptionInfraFactory
	salesConsumer                *consumer.SalesConsumer
	salesConsumerCancel          context.CancelFunc
	subscriptionConsumer         *consumer.SubscriptionConsumer // new
	subscriptionConsumerCancel   context.CancelFunc             // new
	outboxRepo                   outbox.Repository
	idempotencyStore             idempotency.Store
	outboxProcessor              *outbox.Processor
	outboxCancel                 context.CancelFunc
	emailSender                  email.Sender

	attendanceFactory *AttendanceFactory
}

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

// NewFactory creates and initializes the application factory.
func NewFactory() (*Factory, error) {
	cfg := config.LoadConfig()
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

	f.outboxRepo = outbox.NewPostgresRepository(f.PostgresClient().DB)
	pgStore := idempotency.NewPostgresStore(f.PostgresClient().DB)
	redisCache := idempotency.NewRedisCache(f.RedisClient(), 24*time.Hour)
	f.idempotencyStore = idempotency.NewHybridStore(pgStore, redisCache)

	academicsInfra, err := NewAcademicsInfraFactory(
		f.PostgresClient(),
		f.RedisClient(),
		f.outboxRepo,
		f.EncryptionManager(),
		&kafkaEventPublisher{producer: f.KafkaProducer()},
		f.GetAuditService(),
		f.emailSender,
		f.GetSessionService(),
		f.logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize academics/infra factory: %w", err)
	}
	f.academicsInfra = academicsInfra

	f.emailSender = email.NewSMTPSender(email.SMTPConfig{
		Host:     f.config.Email.SMTPHost,
		Port:     f.config.Email.SMTPPort,
		Username: f.config.Email.SMTPUsername,
		Password: f.config.Email.SMTPPassword,
		From:     f.config.Email.FromAddress,
	}, f.logger)
	if f.emailSender == nil {
		logger.Warn("Email sender not configured, emails will not be sent")
	}

	accountingInfra, err := NewAccountingInfraFactory(
		f.PostgresClient(),
		f.RedisClient(),
		f.outboxRepo,
		&kafkaEventPublisher{producer: f.KafkaProducer()},
		f.GetAuditService(),
		f.GetSessionService(),
		f.logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize accounting infra factory: %w", err)
	}
	f.accountingInfra = accountingInfra

	inventoryInfra, err := NewInventoryInfraFactory(
		f.PostgresClient(),
		f.RedisClient(),
		f.outboxRepo,
		&kafkaEventPublisher{producer: f.KafkaProducer()},
		f.GetAuditService(),
		f.EncryptionManager(),
		f.logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize inventory infra factory: %w", err)
	}
	f.inventoryInfra = inventoryInfra

	// -------------------------------------------------------------
	// SALES INFRA – initially with nil updater
	// -------------------------------------------------------------
	salesInfra := NewSalesInfraFactory(
		f.PostgresClient(),
		f.outboxRepo,
		f.idempotencyStore,
		f.GetAuditService(),
		f.EncryptionManager(),
		f.accountingInfra.TaxEngineService(),
		nil, // placeholder – will be set after subscription infra is created
		f.logger,
	)
	f.salesInfra = salesInfra

	// -------------------------------------------------------------
	// SUBSCRIPTION INFRA
	// -------------------------------------------------------------
	subscriptionInfra := NewSubscriptionInfraFactory(
		f.PostgresClient(),
		f.outboxRepo,
		f.idempotencyStore,
		f.GetAuditService(),
		f.logger,
		f.salesInfra.PricingService(),
		f.salesInfra.CouponService(),
		f.salesInfra.DiscountEngineService(),
		f.salesInfra.TaxIntegrationService(),
		f.salesInfra.InvoiceService(),
	)
	f.subscriptionInfra = subscriptionInfra

	// -------------------------------------------------------------
	// INJECT UPDATER INTO SALES INFRA
	// -------------------------------------------------------------
	f.salesInfra.SetPlanItemUpdater(f.subscriptionInfra.PlanItemService())

	// -------------------------------------------------------------
	// ATTENDANCE FACTORY
	// -------------------------------------------------------------
	attendanceFactory := NewAttendanceFactory(
		f.PostgresClient(),
		f.RedisClient(),
		f.KafkaProducer(),
		f.outboxRepo,
		f.idempotencyStore,
		f.GetAuditService(),
		f.config,
		f.logger,
		AttendanceFactoryConfig{
			DeviceTokenPrefix:   f.config.HR.Attendance.DeviceTokenPrefix,
			DeviceTokenSecret:   f.config.HR.Attendance.DeviceTokenSecret,
			DeviceTokenValidity: f.config.HR.Attendance.DeviceTokenValidity,
		},
		f.EncryptionManager(),
	)
	f.attendanceFactory = attendanceFactory

	// -------------------------------------------------------------
	// NEW: INJECT CUSTOMER RESOLVER & USAGE INTEGRATION DEPENDENCIES
	// -------------------------------------------------------------
	// Create repositories needed for customer resolver and usage.
	// Note: we use the imported salesRepo and subRepo packages.
	// -------------------------------------------------------------
	// NEW: INJECT CUSTOMER RESOLVER & USAGE INTEGRATION DEPENDENCIES
	// -------------------------------------------------------------
	// Create repositories needed for customer resolver and usage.
	// Note: these constructors only accept a logger; they use the global DB.
	customerRepo := salesRepo.NewCustomerRepository(f.logger)
	subscriptionRepo := subRepo.NewSubscriptionRepository(f.logger)
	trialRepo := subRepo.NewTrialRepository(f.logger)
	subItemRepo := subRepo.NewSubscriptionItemRepository(f.logger)
	planItemRepo := subRepo.NewPlanItemRepository(f.logger)
	entitlementRepo := subRepo.NewEntitlementRepository(f.logger)
	usageRepo := subRepo.NewUsageRepository(f.logger)

	// Set customer resolver dependencies (for SubjectResolver)
	attendanceFactory.SetCustomerResolverDependencies(customerRepo, subscriptionRepo, trialRepo)

	// Create and set usage integration service – pass the underlying *sql.DB
	usageSvc := usage_integration.NewUsageIntegrationService(
		f.PostgresClient().DB, // <-- *sql.DB
		subscriptionRepo,
		subItemRepo,
		planItemRepo,
		entitlementRepo,
		usageRepo,
		f.logger,
	)
	attendanceFactory.SetUsageIntegrationService(usageSvc)

	// -------------------------------------------------------------

	// Start attendance background services
	ctx := context.Background()
	f.attendanceFactory.StartBackgroundServices(ctx)

	// Kafka logging
	kafkaLoggingMgr, err := f.InitializeKafkaLogging()
	if err != nil {
		logger.Error("failed to initialize Kafka logging", zap.Error(err))
	}
	f.kafkaLoggingMgr = kafkaLoggingMgr

	if f.kafkaProducer != nil {
		f.outboxProcessor = outbox.NewProcessor(
			f.outboxRepo,
			f.kafkaProducer,
			f.logger,
		)
		ctx, cancel := context.WithCancel(context.Background())
		f.outboxCancel = cancel
		go f.outboxProcessor.Start(ctx)
		f.logger.Info("Central outbox processor started – handles all domains (sales, accounting, inventory, academics, etc.)")
	} else {
		f.logger.Error("Kafka producer not available – central outbox disabled")
	}

	ctx2 := context.Background()
	if err := f.InitializeRBAC(ctx2); err != nil {
		return nil, fmt.Errorf("failed to initialize RBAC permission registry: %w", err)
	}

	if err := f.initializeDocumentStorage(); err != nil {
		return nil, err
	}

	if outbox := f.GetAuditOutboxService(); outbox != nil {
		ctx, cancel := context.WithCancel(context.Background())
		f.auditOutboxCancel = cancel
		go func() {
			if err := outbox.Start(ctx); err != nil {
				f.logger.Error(
					"Audit outbox service stopped with error",
					zap.Error(err),
				)
			}
		}()
		f.logger.Info("Audit outbox service started")
	}

	f.initializePayrollWorker()

	// Analytics, student, accounting, inventory, sales consumers
	if f.kafkaProducer != nil && len(f.config.Kafka.Brokers) > 0 {
		analyticsTopic := "academics-events"
		analyticsKafkaConsumer, err := client.NewKafkaConsumer(
			f.config,
			analyticsTopic,
			"analytics-consumer-group",
			f.logger,
		)
		if err != nil {
			f.logger.Error("Failed to create analytics Kafka consumer", zap.Error(err))
		} else {
			analyticsSvc := f.academicsInfra.AnalyticsService()
			analyticsRepo := f.academicsInfra.AnalyticsRepo()
			f.analyticsConsumer = consumer.NewAnalyticsConsumer(
				analyticsSvc,
				analyticsRepo,
				f.postgresClient,
				f.logger,
				analyticsKafkaConsumer,
				analyticsTopic,
				f.config.Kafka.Brokers,
			)
			ctx, cancel := context.WithCancel(context.Background())
			f.analyticsConsumerCancel = cancel
			go func() {
				f.analyticsConsumer.Start(ctx)
				f.logger.Info("Analytics consumer stopped")
			}()
			f.logger.Info("Analytics consumer started", zap.String("topic", analyticsTopic))
		}

		studentTopics := []string{"academics-events"}
		studentConsumers := make(map[string]*client.KafkaConsumer)
		for _, topic := range studentTopics {
			kc, err := client.NewKafkaConsumer(
				f.config,
				topic,
				"student-consumer-group",
				f.logger,
			)
			if err != nil {
				f.logger.Error("Failed to create student Kafka consumer", zap.String("topic", topic), zap.Error(err))
				continue
			}
			studentConsumers[topic] = kc
		}
		if len(studentConsumers) > 0 {
			f.studentConsumer = consumer.NewStudentConsumer(studentConsumers, f.config.Kafka.Brokers)
			ctx, cancel := context.WithCancel(context.Background())
			f.studentConsumerCancel = cancel
			go func() {
				if err := f.studentConsumer.Start(ctx); err != nil && err != context.Canceled {
					f.logger.Error("Student consumer stopped with error", zap.Error(err))
				}
			}()
			f.logger.Info("Student consumer started", zap.Strings("topics", studentTopics))
		} else {
			f.logger.Warn("No Kafka consumers created for student consumer – disabled")
		}

		accountingTopic := "accounting-events"
		accountingKafkaConsumer, err := client.NewKafkaConsumer(
			f.config,
			accountingTopic,
			"accounting-consumer-group",
			f.logger,
		)
		if err != nil {
			f.logger.Error("Failed to create accounting Kafka consumer", zap.Error(err))
		} else {
			f.accountingConsumer = consumer.NewAccountingConsumer(
				f.accountingInfra.AccountingAnalyticsService(),
				f.accountingInfra.ComplianceAnalyticsService(),
				f.accountingInfra.TaxAnalyticsService(),
				f.accountingInfra.AnalyticsRepo(),
				f.postgresClient.DB,
				f.logger,
				accountingKafkaConsumer,
				accountingTopic,
				f.config.Kafka.Brokers,
			)
			ctx, cancel := context.WithCancel(context.Background())
			f.accountingConsumerCancel = cancel
			go func() {
				f.accountingConsumer.Start(ctx)
				f.logger.Info("Accounting consumer stopped")
			}()
			f.logger.Info("Accounting consumer started", zap.String("topic", accountingTopic))
		}

		inventoryTopic := "inventory-events"
		inventoryKafkaConsumer, err := client.NewKafkaConsumer(
			f.config,
			inventoryTopic,
			"inventory-consumer-group",
			f.logger,
		)
		if err != nil {
			f.logger.Error("Failed to create inventory Kafka consumer", zap.Error(err))
		} else {
			inventoryAnalyticsSvc := f.inventoryInfra.InventoryAnalyticsService()
			if inventoryAnalyticsSvc == nil {
				f.logger.Error("InventoryAnalyticsService not available, cannot start inventory consumer")
			} else {
				f.inventoryConsumer = consumer.NewInventoryConsumer(
					inventoryAnalyticsSvc,
					f.logger,
					inventoryKafkaConsumer,
					inventoryTopic,
					f.config.Kafka.Brokers,
				)
				ctx, cancel := context.WithCancel(context.Background())
				f.inventoryConsumerCancel = cancel
				go func() {
					f.inventoryConsumer.Start(ctx)
					f.logger.Info("Inventory consumer stopped")
				}()
				f.logger.Info("Inventory consumer started", zap.String("topic", inventoryTopic))
			}
		}

		salesTopic := "sales-events"
		salesKafkaConsumer, err := client.NewKafkaConsumer(
			f.config,
			salesTopic,
			"sales-consumer-group",
			f.logger,
		)
		if err != nil {
			f.logger.Error("Failed to create sales Kafka consumer", zap.Error(err))
		} else {
			salesAnalyticsSvc := f.salesInfra.SalesAnalyticsService()
			f.salesConsumer = consumer.NewSalesConsumer(
				salesAnalyticsSvc,
				f.logger,
				salesKafkaConsumer,
				salesTopic,
				f.config.Kafka.Brokers,
			)
			ctx, cancel := context.WithCancel(context.Background())
			f.salesConsumerCancel = cancel
			go func() {
				f.salesConsumer.Start(ctx)
				f.logger.Info("Sales consumer stopped")
			}()
			f.logger.Info("✅ Sales consumer started", zap.String("topic", salesTopic))
		}

		// -------------------------------------------------------------
		// NEW: SUBSCRIPTION CONSUMER FOR PRODUCT SYNC
		// -------------------------------------------------------------
		subscriptionTopic := "subscription-events"
		subscriptionKafkaConsumer, err := client.NewKafkaConsumer(
			f.config,
			subscriptionTopic,
			"subscription-product-sync-group",
			f.logger,
		)
		if err != nil {
			f.logger.Error("Failed to create subscription Kafka consumer", zap.Error(err))
		} else {
			productSyncSvc := f.salesInfra.ProductSyncService() // implements SubscriptionAnalyticsService
			f.subscriptionConsumer = consumer.NewSubscriptionConsumer(
				productSyncSvc,
				f.logger,
				subscriptionKafkaConsumer,
				subscriptionTopic,
				f.config.Kafka.Brokers,
			)
			ctx, cancel := context.WithCancel(context.Background())
			f.subscriptionConsumerCancel = cancel
			go func() {
				f.subscriptionConsumer.Start(ctx)
				f.logger.Info("Subscription consumer stopped")
			}()
			f.logger.Info("✅ Subscription consumer started (product sync)", zap.String("topic", subscriptionTopic))
		}
	} else {
		f.logger.Warn("Kafka not available – analytics, student, accounting, inventory, sales, and subscription consumers disabled")
	}

	return f, nil
}
func (f *Factory) Close() error {
	f.closeOnce.Do(func() {
		close(f.closed)

		// Stop attendance factory background services
		if f.attendanceFactory != nil {
			f.attendanceFactory.StopBackgroundServices()
			f.logger.Info("Attendance background services stopped")
		}

		if f.kafkaLoggingMgr != nil {
			if f.kafkaLoggingMgr.cancelCtx != nil {
				f.kafkaLoggingMgr.cancelCtx()
			}
			f.kafkaLoggingMgr.wg.Wait()
			if f.kafkaLoggingMgr.producer != nil {
				if err := f.kafkaLoggingMgr.producer.Close(); err != nil {
					f.logger.Error("Failed to close Kafka producer", zap.Error(err))
				}
			}
		}

		if f.kafkaProducer != nil {
			if err := f.kafkaProducer.Close(); err != nil {
				f.logger.Error("Failed to close Kafka producer", zap.Error(err))
			} else {
				f.logger.Info("Kafka producer closed successfully")
			}
		}

		if f.auditOutboxCancel != nil {
			f.logger.Info("Stopping audit outbox service...")
			f.auditOutboxCancel()
		}

		if f.payrollWorkerCancel != nil {
			f.logger.Info("Stopping payroll worker...")
			f.payrollWorkerCancel()
		}

		if f.analyticsConsumerCancel != nil {
			f.logger.Info("Stopping analytics consumer...")
			f.analyticsConsumerCancel()
		}
		if f.studentConsumerCancel != nil {
			f.logger.Info("Stopping student consumer...")
			f.studentConsumerCancel()
		}
		if f.analyticsConsumer != nil {
			if err := f.analyticsConsumer.Close(); err != nil {
				f.logger.Error("Failed to close analytics consumer", zap.Error(err))
			}
		}
		if f.studentConsumer != nil {
			if err := f.studentConsumer.Close(); err != nil {
				f.logger.Error("Failed to close student consumer", zap.Error(err))
			}
		}
		if f.accountingConsumerCancel != nil {
			f.logger.Info("Stopping accounting consumer...")
			f.accountingConsumerCancel()
		}
		if f.accountingConsumer != nil {
			if err := f.accountingConsumer.Close(); err != nil {
				f.logger.Error("Failed to close accounting consumer", zap.Error(err))
			}
		}
		if f.inventoryConsumerCancel != nil {
			f.logger.Info("Stopping inventory consumer...")
			f.inventoryConsumerCancel()
		}
		if f.inventoryConsumer != nil {
			if err := f.inventoryConsumer.Close(); err != nil {
				f.logger.Error("Failed to close inventory consumer", zap.Error(err))
			}
		}
		if f.salesConsumerCancel != nil {
			f.logger.Info("Stopping sales consumer...")
			f.salesConsumerCancel()
		}
		if f.salesConsumer != nil {
			if err := f.salesConsumer.Close(); err != nil {
				f.logger.Error("Failed to close sales consumer", zap.Error(err))
			}
		}
		// NEW: Close subscription consumer
		if f.subscriptionConsumerCancel != nil {
			f.logger.Info("Stopping subscription consumer...")
			f.subscriptionConsumerCancel()
		}
		if f.subscriptionConsumer != nil {
			if err := f.subscriptionConsumer.Close(); err != nil {
				f.logger.Error("Failed to close subscription consumer", zap.Error(err))
			}
		}
		if f.outboxCancel != nil {
			f.outboxCancel()
			f.logger.Info("Central outbox processor stopped")
		}
		if f.accountingInfra != nil {
			f.accountingInfra.Close()
		}
		if f.inventoryInfra != nil {
			f.inventoryInfra.Close()
		}
		if f.salesInfra != nil {
			f.salesInfra.Close()
		}
		if f.subscriptionInfra != nil {
			f.subscriptionInfra.Close()
			f.logger.Info("Subscription infra closed")
		}
		if f.postgresClient != nil {
			f.postgresClient.Close()
		}
		if f.clickhouseClient != nil {
			f.clickhouseClient.Close()
		}
		if f.esClient != nil {
			f.esClient.Close()
		}
		if f.serviceFactory != nil {
			f.serviceFactory.Cleanup()
		}
		if f.scyllaClient != nil {
			f.scyllaClient.Close()
		}
		if f.redisClient != nil {
			f.redisClient.Close()
		}
		if f.encryptionManager != nil {
			f.encryptionManager.ClearCache()
		}
		if f.wsService != nil {
			if closer, ok := interface{}(f.wsService).(interface{ Close() error }); ok {
				_ = closer.Close()
			}
		}
	})
	return nil
}

// ----------------------------------------------------------------------------
// All getters and helper methods (unchanged from the original)
// ----------------------------------------------------------------------------

func (f *Factory) PayrollJobRepository() payrollrepo.PayrollJobRepository {
	if f.payrollJobRepo == nil {
		f.payrollJobRepo = payrollrepo.NewPayrollJobRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.payrollJobRepo
}

func (f *Factory) ComponentRepository() payrollrepo.ComponentRepository {
	if f.componentRepo == nil {
		f.componentRepo = payrollrepo.NewComponentRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.componentRepo
}

func (f *Factory) CompanySettingsRepository() payrollrepo.CompanySettingsRepository {
	if f.companySettingsRepo == nil {
		f.companySettingsRepo = payrollrepo.NewCompanySettingsRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.companySettingsRepo
}

func (f *Factory) ArrearsRepository() payrollrepo.ArrearsRepository {
	if f.arrearsRepo == nil {
		f.arrearsRepo = payrollrepo.NewArrearsRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.arrearsRepo
}

func (f *Factory) LoanRepository() payrollrepo.LoanRepository {
	if f.loanRepo == nil {
		f.loanRepo = payrollrepo.NewLoanRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.loanRepo
}

func (f *Factory) BankDetailsRepository() payrollrepo.BankDetailsRepository {
	if f.bankDetailsRepo == nil {
		f.bankDetailsRepo = payrollrepo.NewBankDetailsRepository(
			f.PostgresClient(),
			f.EncryptionManager(),
			f.logger,
		)
	}
	return f.bankDetailsRepo
}

func (f *Factory) PayslipRepository() payrollrepo.PayslipRepository {
	if f.payslipRepo == nil {
		f.payslipRepo = payrollrepo.NewPayslipRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.payslipRepo
}

func (f *Factory) TaxDeclarationRepository() payrollrepo.TaxDeclarationRepository {
	if f.taxDeclarationRepo == nil {
		f.taxDeclarationRepo = payrollrepo.NewTaxDeclarationRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.taxDeclarationRepo
}

type stubArrearsService struct{}

func (s *stubArrearsService) GenerateArrearsForSalaryChange(ctx context.Context, companyID, userID uuid.UUID, previousSalaryID, newSalaryID uuid.UUID, effectiveFrom time.Time) error {
	return nil
}
func (s *stubArrearsService) GenerateArrearsForSalaryEnd(ctx context.Context, companyID, userID uuid.UUID, salaryID uuid.UUID, endDate time.Time) error {
	return nil
}

func (f *Factory) ArrearsService() payrollsvc.ArrearsService {
	if f.arrearsSvc == nil {
		f.arrearsSvc = &stubArrearsService{}
	}
	return f.arrearsSvc
}

func (f *Factory) BankExportService() payrollsvc.BankExportService {
	if f.bankExportSvc == nil {
		f.bankExportSvc = payrollsvc.NewBankExportService(
			f.PayrollRepository(),
			f.BankDetailsRepository(),
			f.logger,
		)
	}
	return f.bankExportSvc
}

func (f *Factory) ComponentService() payrollsvc.ComponentService {
	if f.componentSvc == nil {
		f.componentSvc = payrollsvc.NewComponentService(
			f.ComponentRepository(),
			f.CompanySettingsRepository(),
			f.logger,
		)
	}
	return f.componentSvc
}

func (f *Factory) LoanService() payrollsvc.LoanService {
	if f.loanSvc == nil {
		f.loanSvc = payrollsvc.NewLoanService(
			f.LoanRepository(),
			f.ComponentRepository(),
			f.CompanySettingsRepository(),
			f.CompensationService(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.loanSvc
}

func (f *Factory) PayslipService() payrollsvc.PayslipService {
	if f.payslipSvc == nil {
		f.payslipSvc = payrollsvc.NewPayslipService(
			f.PayslipRepository(),
			f.emailSender,
			f.logger,
		)
	}
	return f.payslipSvc
}

func (f *Factory) ReportingService() payrollsvc.ReportingService {
	if f.reportingSvc == nil {
		f.reportingSvc = payrollsvc.NewReportingService(
			f.PayrollRepository(),
			f.logger,
		)
	}
	return f.reportingSvc
}

func (f *Factory) TaxDeclarationService() payrollsvc.TaxDeclarationService {
	if f.taxDeclarationSvc == nil {
		f.taxDeclarationSvc = payrollsvc.NewTaxDeclarationService(
			f.TaxDeclarationRepository(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.taxDeclarationSvc
}

func (f *Factory) AttendanceRuleService() payrollsvc.AttendanceRuleService {
	if f.attendanceRuleSvc == nil {
		f.attendanceRuleSvc = payrollsvc.NewAttendanceRuleService(
			f.AttendanceRuleRepository(),
			f.ComponentRepository(),
			f.logger,
		)
	}
	return f.attendanceRuleSvc
}

func (f *Factory) EmployeeFineService() payrollsvc.EmployeeFineService {
	if f.employeeFineSvc == nil {
		f.employeeFineSvc = payrollsvc.NewEmployeeFineService(
			f.EmployeeFineRepository(),
			f.PayrollRepository(),
			f.ComponentRepository(),
			f.CompanySettingsRepository(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.employeeFineSvc
}

func (f *Factory) PayrollEngineService() payrollsvc.PayrollEngineService {
	if f.payrollEngineSvc == nil {
		f.payrollEngineSvc = payrollsvc.NewPayrollEngineService(
			f.PayrollRepository(),
			f.PayrollJobRepository(),
			f.CompensationService(),
			f.StatutoryEngine(),
			f.GetAttendancePayrollBridge(),
			f.GetAuditService(),
			f.AttendanceRuleRepository(),
			f.EmployeeFineRepository(),
			f.ArrearsRepository(),
			f.LoanRepository(),
			f.ComponentRepository(),
			f.CompanySettingsRepository(),
			f.logger,
		)
	}
	return f.payrollEngineSvc
}

func (f *Factory) PayrollQueryService() payrollsvc.PayrollQueryService {
	if f.payrollQuerySvc == nil {
		f.payrollQuerySvc = payrollsvc.NewPayrollQueryService(
			f.PayrollRepository(),
			f.BankDetailsRepository(),
			f.PayslipRepository(),
			f.PDFGenerator(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.payrollQuerySvc
}

func (f *Factory) SalaryStructureService() payrollsvc.SalaryStructureService {
	if f.salaryStructureSvc == nil {
		f.salaryStructureSvc = payrollsvc.NewSalaryStructureService(
			f.CompensationRepository(),
			f.PayrollLockService(),
			f.CompensationService(),
			f.ArrearsService(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.salaryStructureSvc
}

func (f *Factory) AttendanceRuleRepository() payrollrepo.AttendanceRuleRepository {
	if f.attendanceRuleRepo == nil {
		f.attendanceRuleRepo = payrollrepo.NewAttendanceRuleRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.attendanceRuleRepo
}

func (f *Factory) GetAttendanceRuleHandler() *payrollhandler.AttendanceRuleHandler {
	if f.attendanceRuleHandler == nil {
		f.attendanceRuleHandler = payrollhandler.NewAttendanceRuleHandler(
			f.AttendanceRuleService(),
			f.logger,
		)
	}
	return f.attendanceRuleHandler
}

func (f *Factory) EmployeeFineRepository() payrollrepo.EmployeeFineRepository {
	if f.employeeFineRepo == nil {
		f.employeeFineRepo = payrollrepo.NewEmployeeFineRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.employeeFineRepo
}

func (f *Factory) GetEmployeeFineHandler() *payrollhandler.EmployeeFineHandler {
	if f.employeeFineHandler == nil {
		f.employeeFineHandler = payrollhandler.NewEmployeeFineHandler(
			f.EmployeeFineService(),
			f.logger,
		)
	}
	return f.employeeFineHandler
}

func (f *Factory) CompensationRepository() payrollrepo.CompensationRepository {
	if f.compensationRepo == nil {
		f.compensationRepo = payrollrepo.NewCompensationRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.compensationRepo
}

func (f *Factory) SalaryStructureRepository() payrollrepo.SalaryStructureRepository {
	if f.salaryStructureRepo == nil {
		f.salaryStructureRepo = payrollrepo.NewSalaryStructureRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.salaryStructureRepo
}

func (f *Factory) StatutoryProfileRepository() payrollrepo.StatutoryProfileRepository {
	if f.statutoryProfileRepo == nil {
		f.statutoryProfileRepo = payrollrepo.NewStatutoryProfileRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.statutoryProfileRepo
}

func (f *Factory) StatutoryRepository() payrollrepo.StatutoryRepository {
	if f.statutoryRepo == nil {
		f.statutoryRepo = payrollrepo.NewStatutoryRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.statutoryRepo
}

func (f *Factory) PayrollRepository() payrollrepo.PayrollRepository {
	if f.payrollRepository == nil {
		f.payrollRepository = payrollrepo.NewPayrollRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.payrollRepository
}

func (f *Factory) CompensationService() payrollsvc.CompensationService {
	if f.compensationSvc == nil {
		f.compensationSvc = payrollsvc.NewCompensationService(
			f.CompensationRepository(),
			f.PayrollRepository(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.compensationSvc
}

func (f *Factory) PayrollAdjustmentService() payrollsvc.PayrollAdjustmentService {
	if f.payrollAdjustmentSvc == nil {
		f.payrollAdjustmentSvc = payrollsvc.NewPayrollAdjustmentService(
			f.PayrollRepository(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.payrollAdjustmentSvc
}

func (f *Factory) PayrollLockService() payrollsvc.PayrollLockService {
	if f.payrollLockSvc == nil {
		f.payrollLockSvc = payrollsvc.NewPayrollLockService(
			f.PayrollRepository(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.payrollLockSvc
}

func (f *Factory) GetInventoryHandlers() *inventory.InventoryHandlers {
	return f.inventoryInfra.InventoryHandlers()
}

func (f *Factory) StatutoryProfileService() payrollsvc.StatutoryProfileService {
	if f.statutoryProfileSvc == nil {
		f.statutoryProfileSvc = payrollsvc.NewStatutoryProfileService(
			f.StatutoryProfileRepository(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.statutoryProfileSvc
}

func (f *Factory) StatutoryEngine() payrollsvc.StatutoryEngine {
	if f.statutoryEngineSvc == nil {
		f.statutoryEngineSvc = payrollsvc.NewStatutoryEngine(
			f.StatutoryRepository(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.statutoryEngineSvc
}

func (f *Factory) GetCompensationHandler() *payrollhandler.CompensationHandler {
	if f.compensationHandler == nil {
		f.compensationHandler = payrollhandler.NewCompensationHandler(
			f.CompensationService(),
			f.logger,
		)
	}
	return f.compensationHandler
}

func (f *Factory) GetPayrollAdjustmentHandler() *payrollhandler.PayrollAdjustmentHandler {
	if f.payrollAdjustmentHandler == nil {
		f.payrollAdjustmentHandler = payrollhandler.NewPayrollAdjustmentHandler(
			f.PayrollAdjustmentService(),
			f.logger,
		)
	}
	return f.payrollAdjustmentHandler
}

func (f *Factory) GetPayrollLockHandler() *payrollhandler.PayrollLockHandler {
	if f.payrollLockHandler == nil {
		f.payrollLockHandler = payrollhandler.NewPayrollLockHandler(
			f.PayrollLockService(),
			f.logger,
		)
	}
	return f.payrollLockHandler
}

func (f *Factory) GetPayrollCommandHandler() *payrollhandler.PayrollCommandHandler {
	if f.payrollCommandHandler == nil {
		f.payrollCommandHandler = payrollhandler.NewPayrollCommandHandler(
			f.PayrollEngineService(),
			f.logger,
		)
	}
	return f.payrollCommandHandler
}

func (f *Factory) GetPayrollQueryHandler() *payrollhandler.PayrollQueryHandler {
	if f.payrollQueryHandler == nil {
		f.payrollQueryHandler = payrollhandler.NewPayrollQueryHandler(
			f.PayrollQueryService(),
			f.logger,
		)
	}
	return f.payrollQueryHandler
}

func (f *Factory) GetPayrollRunHandler() *payrollhandler.PayrollRunHandler {
	if f.payrollRunHandler == nil {
		f.payrollRunHandler = payrollhandler.NewPayrollRunHandler(
			f.PayrollEngineService(),
			f.PayrollQueryService(),
			f.PayrollJobRepository(),
			f.logger,
		)
	}
	return f.payrollRunHandler
}

func (f *Factory) GetSalaryStructureHandler() *payrollhandler.SalaryStructureHandler {
	if f.salaryStructureHandler == nil {
		f.salaryStructureHandler = payrollhandler.NewSalaryStructureHandler(
			f.SalaryStructureService(),
			f.logger,
		)
	}
	return f.salaryStructureHandler
}

func (f *Factory) GetStatutoryProfileHandler() *payrollhandler.StatutoryProfileHandler {
	if f.statutoryProfileHandler == nil {
		f.statutoryProfileHandler = payrollhandler.NewStatutoryProfileHandler(
			f.StatutoryProfileService(),
			f.StatutoryEngine(),
			f.logger,
		)
	}
	return f.statutoryProfileHandler
}

func (f *Factory) GetBankExportHandler() *payrollhandler.BankExportHandler {
	if f.bankExportHandler == nil {
		f.bankExportHandler = payrollhandler.NewBankExportHandler(
			f.BankExportService(),
			f.logger,
		)
	}
	return f.bankExportHandler
}

func (f *Factory) GetComponentHandler() *payrollhandler.ComponentHandler {
	if f.componentHandler == nil {
		f.componentHandler = payrollhandler.NewComponentHandler(
			f.ComponentService(),
			f.logger,
		)
	}
	return f.componentHandler
}

func (f *Factory) GetLoanHandler() *payrollhandler.LoanHandler {
	if f.loanHandler == nil {
		f.loanHandler = payrollhandler.NewLoanHandler(
			f.LoanService(),
			f.logger,
		)
	}
	return f.loanHandler
}

func (f *Factory) GetPayslipHandler() *payrollhandler.PayslipHandler {
	if f.payslipHandler == nil {
		f.payslipHandler = payrollhandler.NewPayslipHandler(
			f.PayslipService(),
			f.logger,
		)
	}
	return f.payslipHandler
}

func (f *Factory) GetReportingHandler() *payrollhandler.ReportingHandler {
	if f.reportingHandler == nil {
		f.reportingHandler = payrollhandler.NewReportingHandler(
			f.ReportingService(),
			f.logger,
		)
	}
	return f.reportingHandler
}

func (f *Factory) GetTaxDeclarationHandler() *payrollhandler.TaxDeclarationHandler {
	if f.taxDeclarationHandler == nil {
		f.taxDeclarationHandler = payrollhandler.NewTaxDeclarationHandler(
			f.TaxDeclarationService(),
			f.logger,
		)
	}
	return f.taxDeclarationHandler
}

func (f *Factory) RedisClient() *client.RedisClient {
	if f.redisClient == nil {
		client, err := client.NewRedisClient(f.config, f.logger)
		if err != nil {
			f.logger.Fatal("Failed to initialize Redis client", zap.Error(err))
		}
		f.redisClient = client
	}
	return f.redisClient
}

func (f *Factory) KafkaProducer() *client.KafkaProducer {
	if f.kafkaProducer == nil {
		producer, err := client.NewKafkaProducer(f.config, f.logger)
		if err != nil {
			f.logger.Fatal("Failed to initialize Kafka producer", zap.Error(err))
		}
		f.kafkaProducer = producer
	}
	return f.kafkaProducer
}

// ----- Attendance factory delegation -----

func (f *Factory) GetAttendancePayrollBridge() hrservice.AttendancePayrollBridge {
	// Use attendance factory's repositories to create the bridge
	return hrservice.NewAttendancePayrollBridge(
		f.attendanceFactory.SummaryRepository(),
		f.attendanceFactory.EventRepository(),
		f.logger,
	)
}

// ----- Legacy HR repositories (kept) -----

func (f *Factory) HREmployeeRepository() hrpostgres.EmployeeRepository {
	if f.hrEmployeeRepository == nil {
		f.hrEmployeeRepository = hrpostgres.NewEmployeeRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.hrEmployeeRepository
}

func (f *Factory) OrgUnitRepository() hrpostgres.OrgUnitRepository {
	if f.orgUnitRepository == nil {
		f.orgUnitRepository = hrpostgres.NewOrgUnitRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.orgUnitRepository
}

func (f *Factory) LeaveRepository() leaverepo.LeaveRepository {
	if f.leaveRepository == nil {
		f.leaveRepository = leaverepo.NewLeaveRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.leaveRepository
}

func (f *Factory) AuditRepository() audit.AuditRepository {
	if f.auditRepository == nil {
		f.auditRepository = audit.NewAuditRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.auditRepository
}

// ----- Services -----

func (f *Factory) GetEmployeeService() *hrservice.EmployeeService {
	if f.employeeService == nil {
		f.employeeService = hrservice.NewEmployeeService(
			f.HREmployeeRepository(),
			f.GetAuditService(),
			hrservice.EmployeeServiceConfig{
				MaxDocumentSizeMB: f.config.HR.Documents.MaxSizeMB,
				DocumentStorage:   f.DocumentStorage(),
			},
			f.logger,
		)
	}
	return f.employeeService
}

func (f *Factory) GetEmployeeQueryService() *hrservice.EmployeeQueryService {
	if f.employeeQueryService == nil {
		f.employeeQueryService = hrservice.NewEmployeeQueryService(
			f.HREmployeeRepository(),
			f.DocumentStorage(),
			f.logger,
		)
	}
	return f.employeeQueryService
}

func (f *Factory) GetOrgUnitService() *hrservice.OrgUnitService {
	if f.orgUnitService == nil {
		f.orgUnitService = hrservice.NewOrgUnitService(
			f.OrgUnitRepository(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.orgUnitService
}

func (f *Factory) GetOrgUnitQueryService() *hrservice.OrgUnitQueryService {
	if f.orgUnitQueryService == nil {
		f.orgUnitQueryService = hrservice.NewOrgUnitQueryService(
			f.OrgUnitRepository(),
			f.logger,
		)
	}
	return f.orgUnitQueryService
}

func (f *Factory) GetAuditService() *audit.AuditService {
	if f.auditService == nil {
		f.auditService = audit.NewAuditService(
			f.AuditRepository(),
			f.logger,
		)
	}
	return f.auditService
}

func (f *Factory) GetAuditQueryService() *audit.AuditQueryService {
	if f.auditQueryService == nil {
		f.auditQueryService = audit.NewAuditQueryService(
			f.AuditRepository(),
			f.logger,
		)
	}
	return f.auditQueryService
}

// ----- Leave -----

func (f *Factory) LeavePolicyService() leavesvc.LeavePolicyService {
	if f.leavePolicyService == nil {
		f.leavePolicyService = leavesvc.NewLeavePolicyService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leavePolicyService
}

func (f *Factory) LeavePolicyConfigService() leavesvc.LeavePolicyConfigService {
	if f.leavePolicyConfigService == nil {
		f.leavePolicyConfigService = leavesvc.NewLeavePolicyConfigService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leavePolicyConfigService
}

func (f *Factory) LeaveAccrualService() leavesvc.LeaveAccrualService {
	if f.leaveAccrualService == nil {
		f.leaveAccrualService = leavesvc.NewLeaveAccrualService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leaveAccrualService
}

func (f *Factory) LeaveQueryService() leavesvc.LeaveQueryService {
	if f.leaveQueryService == nil {
		f.leaveQueryService = leavesvc.NewLeaveQueryService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leaveQueryService
}

func (f *Factory) LeaveBalanceService() leavesvc.LeaveBalanceService {
	if f.leaveBalanceService == nil {
		f.leaveBalanceService = leavesvc.NewLeaveBalanceService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leaveBalanceService
}

func (f *Factory) LeaveRequestService() leavesvc.LeaveRequestService {
	if f.leaveRequestService == nil {
		f.leaveRequestService = leavesvc.NewLeaveRequestService(
			f.LeaveRepository(),
			f.LeaveBalanceService(),
			f.logger,
		)
	}
	return f.leaveRequestService
}

func (f *Factory) GetLeavePolicyResolutionService() leavesvc.LeavePolicyResolutionService {
	if f.leavePolicyResolutionService == nil {
		f.leavePolicyResolutionService = leavesvc.NewLeavePolicyResolutionService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leavePolicyResolutionService
}

func (f *Factory) GetLeavePolicyResolutionHandler() *leavehandler.LeavePolicyResolutionHandler {
	if f.leavePolicyResolutionHandler == nil {
		f.leavePolicyResolutionHandler = leavehandler.NewLeavePolicyResolutionHandler(
			f.GetLeavePolicyResolutionService(),
			f.logger,
		)
	}
	return f.leavePolicyResolutionHandler
}

func (f *Factory) LeaveAdminHandler() *leavehandler.LeaveAdminHandler {
	if f.leaveAdminHandler == nil {
		f.leaveAdminHandler = leavehandler.NewLeaveAdminHandler(
			f.LeavePolicyService(),
			f.LeavePolicyConfigService(),
			f.LeaveAccrualService(),
			f.logger,
		)
	}
	return f.leaveAdminHandler
}

func (f *Factory) LeaveQueryHandler() *leavehandler.LeaveQueryHandler {
	if f.leaveQueryHandler == nil {
		f.leaveQueryHandler = leavehandler.NewLeaveQueryHandler(
			f.LeaveQueryService(),
			f.logger,
		)
	}
	return f.leaveQueryHandler
}

func (f *Factory) LeaveRequestHandler() *leavehandler.LeaveRequestHandler {
	if f.leaveRequestHandler == nil {
		// Use attendance factory's scheduling service directly
		f.leaveRequestHandler = leavehandler.NewLeaveRequestHandler(
			f.LeaveRequestService(),
			f.LeaveQueryService(),
			f.attendanceFactory.SchedulingService(), // from attendance module
			f.logger,
		)
	}
	return f.leaveRequestHandler
}

// ----- Document storage -----

func (f *Factory) initializeDocumentStorage() error {
	cfg := f.config
	basePath := cfg.HR.Documents.BasePath
	maxSizeMB := cfg.HR.Documents.MaxSizeMB
	ds, err := hrservice.NewLocalDocumentStorage(
		basePath,
		maxSizeMB,
		f.logger,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize document storage: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ds.HealthCheck(ctx); err != nil {
		return fmt.Errorf("document storage health check failed: %w", err)
	}
	f.documentStorage = ds
	return nil
}

func (f *Factory) DocumentStorage() hrservice.DocumentStorage {
	if f.documentStorage == nil {
		f.logger.Fatal("Document storage not initialized")
	}
	return f.documentStorage
}

// ----- Payroll worker -----

func (f *Factory) initializePayrollWorker() {
	if f.payrollWorker != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.payrollWorkerCancel = cancel
	workerID := fmt.Sprintf("worker-%s", uuid.New().String())
	maxConcurrentPerCompany := 2
	f.payrollWorker = payrollsvc.NewPayrollWorker(
		f.PayrollJobRepository(),
		f.PayrollEngineService(),
		f.logger,
		workerID,
		maxConcurrentPerCompany,
	)
	go f.payrollWorker.Start(ctx)
	f.logger.Info("Payroll worker started",
		zap.String("worker_id", workerID),
		zap.Int("max_concurrent_per_company", maxConcurrentPerCompany),
	)
}

// ----- Kafka logging -----

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
	f.kafkaProducer = kafkaProducer
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
	if f.config.Elasticsearch.URL != "" && f.esClient != nil {
		esTopics := []string{
			"admin-events",
			"user-events",
			"security-events",
			"session-events",
		}
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
	if f.config.Clickhouse.URL != "" && f.clickhouseClient != nil {
		chTopics := []string{
			"device-events",
			"mpin-events",
			"otp-events",
			"security-events",
		}
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
				f.clickhouseClient,
				1000,
				5*time.Second,
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

func (f *Factory) GetAuditOutboxService() *audit.AuditOutboxService {
	if f.auditOutboxService == nil {
		if f.kafkaProducer == nil {
			f.logger.Warn("Kafka producer not available, audit outbox disabled")
			return nil
		}
		f.auditOutboxService = audit.NewAuditOutboxService(
			f.PostgresClient(),
			f.kafkaProducer,
			500,
			5*time.Second,
			"audit-logs",
		)
	}
	return f.auditOutboxService
}

// ----- Repository getters (kept from previous) -----

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

func (f *Factory) PostgresClient() *client.PostgresClient {
	if f.postgresClient == nil {
		client, err := client.NewPostgresClient(f.config, f.logger)
		if err != nil {
			f.logger.Fatal("Failed to initialize PostgreSQL client", zap.Error(err))
		}
		f.postgresClient = client
	}
	return f.postgresClient
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

func (f *Factory) AdminRepository() postgres.AdminRepository {
	if f.adminRepository == nil {
		f.adminRepository = postgres.NewAdminRepositoryPostgres(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.adminRepository
}

func (f *Factory) GetJWTService() *service.JWTService {
	if f.jwtService == nil {
		f.jwtService = service.NewJWTService(
			f.Config(),
			f.CompanyRepository(),
			f.AdminRepository(),
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

func (f *Factory) GetPhoneValidator() *service.PhoneValidatorImpl {
	phoneValidator := service.NewPhoneValidator(
		f.GetUserService(),
		nil,
		f.logger,
	)
	return phoneValidator
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
		phoneValidator := f.GetPhoneValidator()
		f.otpService = service.NewOTPService(
			repo,
			hasher,
			cfg,
			distCache,
			logger,
			logProducer,
			phoneValidator,
			f.AdminDeviceTrustRepository(),
			f.smsManager,
		)
		if phoneValidator != nil {
			phoneValidator.SetAdminService(f.GetAdminService())
		}
	}
	return f.otpService
}

func (f *Factory) GetAdminService() *service.AdminService {
	if f.adminService == nil {
		f.adminService = service.NewAdminService(
			f.AdminRepository(),
			f.CompanyRepository(),
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

func (f *Factory) GetMPINService() *service.MPINService {
	if f.mpinService == nil {
		mpinRepo := f.MPINRepository()
		userRepo := f.UserRepository()
		deviceTrustRepo := f.GetDeviceTrustRepository()
		userOTPService := f.GetUserOTPService()
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
			userOTPService,
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
		deviceTrustRepo := f.GetDeviceTrustRepository()
		adminDeviceTrustRepo := f.AdminDeviceTrustRepository()
		cfg := f.Config()
		logger := f.logger
		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}
		f.deviceService = service.NewDeviceService(
			deviceRepo,
			deviceTrustRepo,
			adminDeviceTrustRepo,
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

func (f *Factory) GetUserOTPService() *service.UserOTPService {
	if f.userOTPService == nil {
		repo := f.OTPRepository()
		hasher := f.Hasher()
		cfg := f.Config()
		logger := f.logger
		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}
		logProducer := f.GetLogProducerService()
		phoneValidator := f.GetPhoneValidator()
		deviceTrustRepo := f.GetDeviceTrustRepository()
		smsManager := f.GetSMSManager()
		f.userOTPService = service.NewUserOTPService(
			repo,
			hasher,
			cfg,
			distCache,
			logger,
			logProducer,
			phoneValidator,
			deviceTrustRepo,
			smsManager,
		)
		if phoneValidator != nil {
			phoneValidator.SetAdminService(f.GetAdminService())
		}
	}
	return f.userOTPService
}

func (f *Factory) GetPairingRepository() redis.PairingRepository {
	if f.pairingRepo == nil {
		f.pairingRepo = redis.NewPairingRepository(
			f.redisClient.Client(),
			f.logger,
		)
	}
	return f.pairingRepo
}

func (f *Factory) GetHMACUtil() *util.HMACUtil {
	if f.hmacUtil == nil {
		secret := f.config.Security.JWTSecret
		if secret == "" {
			secret = "default-qr-hmac-secret-change-in-production"
		}
		f.hmacUtil = util.NewHMACUtil(secret)
	}
	return f.hmacUtil
}

func (f *Factory) GetQRUtil() *util.QRUtil {
	if f.qrUtil == nil {
		f.qrUtil = util.NewQRUtil(f.config.Security.JWTSecret)
	}
	return f.qrUtil
}

func (f *Factory) GetPairingService() *service.PairingService {
	if f.pairingService == nil {
		f.pairingService = service.NewPairingService(
			f.GetPairingRepository(),
			f.GetSessionService(),
			f.GetQRUtil(),
			f.config,
			f.logger,
		)
	}
	return f.pairingService
}

func (f *Factory) GetWebSocketService() *service.WebSocketService {
	if f.wsService == nil {
		f.wsService = service.NewWebSocketService(f.logger)
		go f.wsService.Run()
		f.logger.Info("WebSocket service started")
	}
	return f.wsService
}

func (f *Factory) GetPairingHandler() *handler.PairingHandler {
	if f.pairingHandler == nil {
		f.pairingHandler = handler.NewPairingHandler(
			f.GetPairingService(),
			f.GetWebSocketService(),
			f.logger,
		)
	}
	return f.pairingHandler
}

func (f *Factory) GetWebSocketHandler() *handler.WebSocketHandler {
	if f.wsHandler == nil {
		f.wsHandler = handler.NewWebSocketHandler(
			f.GetWebSocketService(),
			f.logger,
		)
	}
	return f.wsHandler
}

// ----- Client initialisation -----

func (f *Factory) initializeClients() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var initErrors []error
	if rc, err := client.NewRedisClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("redis: %w", err))
	} else {
		f.redisClient = rc
		if err := f.redisClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("redis health check: %w", err))
		}
	}
	if pgc, err := client.NewPostgresClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("postgres: %w", err))
	} else {
		f.postgresClient = pgc
		if err := f.postgresClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("postgres health check: %w", err))
		}
	}
	if sc, err := scylla.NewScyllaClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("scylla: %w", err))
	} else {
		f.scyllaClient = sc
		if err := f.scyllaClient.HealthCheck(); err != nil {
			initErrors = append(initErrors, fmt.Errorf("scylla health check: %w", err))
		}
	}
	if ec, err := client.NewElasticsearchClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("elasticsearch: %w", err))
	} else {
		f.esClient = ec
		if err := f.esClient.HealthCheck(); err != nil {
			initErrors = append(initErrors, fmt.Errorf("elasticsearch health check: %w", err))
		}
	}
	if chc, err := client.NewClickHouseClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("clickhouse: %w", err))
	} else {
		f.clickhouseClient = chc
		if err := f.clickhouseClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("clickhouse health check: %w", err))
		}
	}
	if len(initErrors) > 0 {
		for _, e := range initErrors {
			f.logger.Error("Client initialization failed", zap.Error(e))
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
	}
	var kmsClient *kms.Client
	if f.config.KMS.Enabled {
		kmsClient = nil
	}
	f.encryptionManager = encryption.NewEncryptionManager(f.config, kmsClient)
	f.bucketingManager = bucketing.NewBucketingManager(f.config)
	f.smsManager = sms.NewSMSManager(f.logger)
	if f.hasher != nil && f.config.IsProduction() {
		f.hasher.StartPepperRotation()
	}
}

// ----- InitializeHandlers -----

func (f *Factory) InitializeHandlers() error {
	logger := f.logger

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
	userOTPService := f.GetUserOTPService()

	// Handlers from other modules
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
	authHandler := handler.NewAuthHandler(
		userOTPService,
		mpinService,
		sessionService,
		userService,
		companyService,
		deviceService,
		jwtService,
		logger,
	)
	f.authHandler = authHandler

	pairingHandler := f.GetPairingHandler()
	wsHandler := f.GetWebSocketHandler()

	// Payroll handlers
	compensationHandler := f.GetCompensationHandler()
	payrollAdjustmentHandler := f.GetPayrollAdjustmentHandler()
	payrollLockHandler := f.GetPayrollLockHandler()
	payrollCommandHandler := f.GetPayrollCommandHandler()
	payrollQueryHandler := f.GetPayrollQueryHandler()
	payrollRunHandler := f.GetPayrollRunHandler()
	salaryStructureHandler := f.GetSalaryStructureHandler()
	statutoryProfileHandler := f.GetStatutoryProfileHandler()
	attendanceRuleHandler := f.GetAttendanceRuleHandler()
	employeeFineHandler := f.GetEmployeeFineHandler()
	bankExportHandler := f.GetBankExportHandler()
	componentHandler := f.GetComponentHandler()
	loanHandler := f.GetLoanHandler()
	payslipHandler := f.GetPayslipHandler()
	reportingHandler := f.GetReportingHandler()
	taxDeclarationHandler := f.GetTaxDeclarationHandler()

	// Academic handlers
	academicHandlers := &handler.AcademicHandlers{
		AcademicYearHandler:      f.academicsInfra.AcademicYearHandler(),
		AdmissionHandler:         f.academicsInfra.AdmissionHandler(),
		AnalyticsHandler:         f.academicsInfra.AnalyticsHandler(),
		AssignmentHandler:        f.academicsInfra.AssignmentHandler(),
		CourseHandler:            f.academicsInfra.CourseHandler(),
		CurriculumHandler:        f.academicsInfra.CurriculumHandler(),
		EnrollmentHandler:        f.academicsInfra.EnrollmentHandler(),
		ExamHandler:              f.academicsInfra.ExamHandler(),
		FeeHandler:               f.academicsInfra.FeeHandler(),
		GradingHandler:           f.academicsInfra.GradingHandler(),
		GuardianHandler:          f.academicsInfra.GuardianHandler(),
		LibraryHandler:           f.academicsInfra.LibraryHandler(),
		NotificationHandler:      f.academicsInfra.NotificationHandler(),
		RoomHandler:              f.academicsInfra.RoomHandler(),
		SectionHandler:           f.academicsInfra.SectionHandler(),
		StudentHandler:           f.academicsInfra.StudentHandler(),
		SubjectHandler:           f.academicsInfra.SubjectHandler(),
		SubmissionHandler:        f.academicsInfra.SubmissionHandler(),
		TeacherHandler:           f.academicsInfra.TeacherHandler(),
		TermHandler:              f.academicsInfra.TermHandler(),
		TimetableHandler:         f.academicsInfra.TimetableHandler(),
		TransportHandler:         f.academicsInfra.TransportHandler(),
		SessionGenerationHandler: f.academicsInfra.SessionGenerationHandler(),
	}

	// Accounting handlers
	accountingHandlers := &accounting.AccountingHandlers{
		AccountHandler:            f.accountingInfra.AccountHandler(),
		LedgerHandler:             f.accountingInfra.LedgerHandler(),
		ReconciliationHandler:     f.accountingInfra.ReconciliationHandler(),
		ReportHandler:             f.accountingInfra.ReportHandler(),
		ComplianceHandler:         f.accountingInfra.ComplianceHandler(),
		JournalHandler:            f.accountingInfra.JournalHandler(),
		TaxHandler:                f.accountingInfra.TaxHandler(),
		AccountingSettingsHandler: f.accountingInfra.AccountingSettingsHandler(),
		AnalyticsHandler:          f.accountingInfra.AnalyticsHandler(),
		PeriodLockHandler:         f.accountingInfra.PeriodLockHandler(),
	}

	// Inventory
	inventoryHandlers := f.GetInventoryHandlers()

	// Sales
	salesHandlers := &sales.SalesHandlers{
		CommissionHandler:  f.salesInfra.CommissionHandler(),
		CouponHandler:      f.salesInfra.CouponHandler(),
		CreditCheckHandler: f.salesInfra.CreditCheckHandler(),
		CreditNoteHandler:  f.salesInfra.CreditNoteHandler(),
		CustomerHandler:    f.salesInfra.CustomerHandler(),
		DiscountHandler:    f.salesInfra.DiscountHandler(),
		InvoiceHandler:     f.salesInfra.InvoiceHandler(),
		OrderHandler:       f.salesInfra.OrderHandler(),
		PaymentHandler:     f.salesInfra.PaymentHandler(),
		PaymentTermHandler: f.salesInfra.PaymentTermHandler(),
		PricingHandler:     f.salesInfra.PricingHandler(),
		ProductHandler:     f.salesInfra.ProductHandler(),
		PromotionHandler:   f.salesInfra.PromotionHandler(),
		QuoteHandler:       f.salesInfra.QuoteHandler(),
		ReportHandler:      f.salesInfra.ReportHandler(),
		ReturnHandler:      f.salesInfra.ReturnHandler(),
		SalesRepHandler:    f.salesInfra.SalesRepHandler(),
		TaxHandler:         f.salesInfra.TaxHandler(),
	}

	// Subscription handlers
	var subscriptionHandlers *subscription.SubscriptionHandlers
	if f.subscriptionInfra != nil {
		subscriptionHandlers = f.subscriptionInfra.SubscriptionHandlers()
		if subscriptionHandlers == nil {
			logger.Warn("Subscription handlers not available from infra")
		}
	} else {
		logger.Warn("Subscription infra not available – subscription routes will not be registered")
	}

	// Attendance handlers
	attendanceIngestHandler := f.attendanceFactory.IngestHandler()
	attendanceAdminHandler := f.attendanceFactory.AdminHandler()
	attendanceQueryHandler := f.attendanceFactory.QueryHandler()
	attendanceExemptionHandler := f.attendanceFactory.ExemptionHandler()
	attendanceResolutionHandler := f.attendanceFactory.ResolutionHandler()
	attendanceCorrectionHandler := f.attendanceFactory.CorrectionHandler()
	attendanceDeviceHandler := f.attendanceFactory.DeviceHandler()
	attendanceEnrollmentHandler := f.attendanceFactory.EnrollmentHandler()
	attendanceTokenAdminHandler := f.attendanceFactory.TokenAdminHandler()
	attendanceHeartbeatHandler := f.attendanceFactory.HeartbeatHandler()
	attendanceBatchHandler := f.attendanceFactory.BatchHandler()
	attendanceSourceAdminHandler := f.attendanceFactory.SourceAdminHandler()
	attendanceWorkCenterHandler := f.attendanceFactory.WorkCenterHandler()
	attendanceSchedulingHandler := f.attendanceFactory.SchedulingHandler()
	attendanceBiometricEnrollmentHandler := f.attendanceFactory.BiometricEnrollmentHandler()
	attendanceBiometricSyncHandler := f.attendanceFactory.BiometricSyncHandler()
	attendanceReportHandler := f.attendanceFactory.ReportHandler()
	deviceAuthMiddleware := f.attendanceFactory.DeviceAuthMiddleware()

	// HR handlers (non-attendance)
	leavePolicyResolutionHandler := f.GetLeavePolicyResolutionHandler()
	orgUnitHandler := f.GetOrgUnitHandler()
	employeeHandler := f.GetHREmployeeHandler()
	leaveAdminHandler := f.LeaveAdminHandler()
	leaveRequestHandler := f.LeaveRequestHandler()
	leaveQueryHandler := f.LeaveQueryHandler()

	// Build the router – now includes subscriptionHandlers
	f.router = handler.NewRouter(
		otpHandler,
		adminHandler,
		authHandler,
		rbacHandler,
		f.GetHRAuditHandler(),
		employeeHandler,
		pairingHandler,
		wsHandler,
		sessionService,
		jwtService,
		logger,
		orgUnitHandler,
		leaveAdminHandler,
		leaveRequestHandler,
		leaveQueryHandler,
		payrollRunHandler,
		leavePolicyResolutionHandler,
		compensationHandler,
		payrollAdjustmentHandler,
		payrollCommandHandler,
		payrollLockHandler,
		payrollQueryHandler,
		payrollRunHandler,
		salaryStructureHandler,
		statutoryProfileHandler,
		attendanceRuleHandler,
		employeeFineHandler,
		bankExportHandler,
		componentHandler,
		loanHandler,
		payslipHandler,
		reportingHandler,
		taxDeclarationHandler,
		academicHandlers,
		accountingHandlers,
		inventoryHandlers,
		salesHandlers,
		subscriptionHandlers, // <-- NEW
		attendanceIngestHandler,
		attendanceQueryHandler,
		attendanceExemptionHandler,
		attendanceResolutionHandler,
		attendanceDeviceHandler,
		attendanceEnrollmentHandler,
		attendanceTokenAdminHandler,
		attendanceSourceAdminHandler,
		attendanceCorrectionHandler,
		attendanceReportHandler,
		attendanceBatchHandler,
		attendanceHeartbeatHandler,
		attendanceBiometricEnrollmentHandler,
		attendanceBiometricSyncHandler,
		attendanceWorkCenterHandler,
		attendanceSchedulingHandler,
		attendanceAdminHandler,
		f.academicsInfra.SessionGenerationHandler(),
		deviceAuthMiddleware,
	)

	logger.Info("Handlers and router initialized with JWT, bitmask, QR web login, attendance, leave, payroll, biometric, accounting, inventory, subscription, and sales systems")
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

func (f *Factory) InitializeRBAC(ctx context.Context) error {
	rbacInitService := f.GetRBACInitService()
	if err := rbacInitService.InitializePermissionRegistry(ctx); err != nil {
		return fmt.Errorf("failed to initialize RBAC permission registry: %w", err)
	}
	f.logger.Info("RBAC permission registry initialized successfully")
	return nil
}

func (f *Factory) HealthCheck(ctx context.Context) map[string]error {
	errs := make(map[string]error)

	if f.postgresClient != nil {
		if err := f.postgresClient.HealthCheck(ctx); err != nil {
			errs["postgres"] = err
		}
	} else {
		errs["postgres"] = fmt.Errorf("postgres client not initialized")
	}

	if f.payrollRepository != nil {
		if err := f.payrollRepository.HealthCheck(ctx); err != nil {
			errs["payroll_repository"] = err
		}
	}
	if f.salaryStructureRepo != nil {
		if err := f.salaryStructureRepo.HealthCheck(ctx); err != nil {
			errs["salary_structure_repository"] = err
		}
	}
	if f.statutoryRepo != nil {
		if err := f.statutoryRepo.HealthCheck(ctx); err != nil {
			errs["statutory_repository"] = err
		}
	}
	if f.leaveRepository != nil {
		if err := f.leaveRepository.HealthCheck(ctx); err != nil {
			errs["leave_repository"] = err
		}
	}
	return errs
}

func (f *Factory) Config() *config.Config                           { return f.config }
func (f *Factory) TLSManager() *tls.TLSManager                      { return f.tlsManager }
func (f *Factory) ScyllaClient() *scylla.ScyllaClient               { return f.scyllaClient }
func (f *Factory) Hasher() *hashing.Hasher                          { return f.hasher }
func (f *Factory) EncryptionManager() *encryption.EncryptionManager { return f.encryptionManager }
func (f *Factory) BucketingManager() *bucketing.BucketingManager    { return f.bucketingManager }
func (f *Factory) GetLogProducerService() *service.LogProducerService {
	if f.kafkaLoggingMgr == nil {
		return nil
	}
	return f.kafkaLoggingMgr.GetLogProducerService()
}
func (f *Factory) GetSMSManager() *sms.SMSManager {
	return f.smsManager
}
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
func (f *Factory) PDFGenerator() payrollsvc.PDFGenerator {
	if f.pdfGenerator == nil {
		f.pdfGenerator = pdf.NewGenerator()
	}
	return f.pdfGenerator
}

// ----- HR handlers (non-attendance) -----

func (f *Factory) GetHRAuditHandler() *audit.AuditHandler {
	if f.hrAuditHandler == nil {
		f.hrAuditHandler = audit.NewAuditHandler(
			f.GetAuditQueryService(),
			f.logger,
		)
	}
	return f.hrAuditHandler
}

func (f *Factory) GetHREmployeeHandler() *hrhandler.EmployeeHandler {
	if f.hrEmployeeHandler == nil {
		f.hrEmployeeHandler = hrhandler.NewEmployeeHandler(
			f.GetEmployeeService(),
			f.GetEmployeeQueryService(),
			f.GetAuditService(),
			f.logger,
			f.config.HR.Documents.MaxSizeMB,
		)
	}
	return f.hrEmployeeHandler
}

func (f *Factory) GetOrgUnitHandler() *hrhandler.OrgUnitHandler {
	if f.orgUnitHandler == nil {
		f.orgUnitHandler = hrhandler.NewOrgUnitHandler(
			f.GetOrgUnitService(),
			f.GetOrgUnitQueryService(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.orgUnitHandler
}

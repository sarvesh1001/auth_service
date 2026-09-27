// internal/factory/factory.go
package factory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"auth-service/internal/repository/clickhouse"
	"auth-service/internal/repository/elasticsearch"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting"
	"auth-service/internal/attendance/service/usage_integration"
	avatarHandler "auth-service/internal/avatar/handler"
	avatarRepo "auth-service/internal/avatar/repository"
	avatarSvc "auth-service/internal/avatar/service"
	"auth-service/internal/bucketing"
	"auth-service/internal/client"
	"auth-service/internal/config"
	"auth-service/internal/consumer"
	"auth-service/internal/email"
	"auth-service/internal/encryption"
	"auth-service/internal/handler"
	locationhandler "auth-service/internal/handler" // 🆕 LOCATION
	"auth-service/internal/hashing"
	"auth-service/internal/hashing/pepperstore"
	hrhandler "auth-service/internal/hr/handler"
	leavehandler "auth-service/internal/hr/leave/handler"
	leaverepo "auth-service/internal/hr/leave/repository"
	leavesvc "auth-service/internal/hr/leave/service"
	leaveworker "auth-service/internal/hr/leave/worker" // 👈 ADD
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
	kycHandler "auth-service/internal/kyc/handler"
	kycRepo "auth-service/internal/kyc/repository"
	kycSvc "auth-service/internal/kyc/service"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/repository/redis"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/sales"
	salesRepo "auth-service/internal/sales/repository"
	"auth-service/internal/service"
	"auth-service/internal/sms"
	"auth-service/internal/storage"
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

	// 👇 ADD
	resolverJobRepo      leaverepo.ResolverJobRepository
	resolverWorker       *leaveworker.ResolverWorker
	resolverWorkerCancel context.CancelFunc

	bankExportSvc              payrollsvc.BankExportService
	componentSvc               payrollsvc.ComponentService
	loanSvc                    payrollsvc.LoanService
	payslipSvc                 payrollsvc.PayslipService
	reportingSvc               payrollsvc.ReportingService
	taxDeclarationSvc          payrollsvc.TaxDeclarationService
	bankExportHandler          *payrollhandler.BankExportHandler
	componentHandler           *payrollhandler.ComponentHandler
	loanHandler                *payrollhandler.LoanHandler
	payslipHandler             *payrollhandler.PayslipHandler
	reportingHandler           *payrollhandler.ReportingHandler
	taxDeclarationHandler      *payrollhandler.TaxDeclarationHandler
	academicsInfra             *AcademicsInfraFactory
	accountingInfra            *AccountingInfraFactory
	analyticsConsumer          *consumer.AnalyticsConsumer
	analyticsConsumerCancel    context.CancelFunc
	inventoryInfra             *InventoryInfraFactory
	studentConsumer            *consumer.StudentConsumer
	studentConsumerCancel      context.CancelFunc
	accountingConsumer         *consumer.AccountingConsumer
	accountingConsumerCancel   context.CancelFunc
	inventoryConsumer          *consumer.InventoryConsumer
	inventoryConsumerCancel    context.CancelFunc
	salesInfra                 *SalesInfraFactory
	subscriptionInfra          *SubscriptionInfraFactory
	salesConsumer              *consumer.SalesConsumer
	salesConsumerCancel        context.CancelFunc
	subscriptionConsumer       *consumer.SubscriptionConsumer
	subscriptionConsumerCancel context.CancelFunc
	outboxRepo                 outbox.Repository
	idempotencyStore           idempotency.Store
	outboxProcessor            *outbox.Processor
	outboxCancel               context.CancelFunc
	emailSender                email.Sender
	analyticsCHRepo            *clickhouse.AnalyticsRepository
	analyticsESRepo            *elasticsearch.AnalyticsESRepository
	analyticsService           *service.AnalyticsService
	analyticsHandler           *handler.AnalyticsHandler

	attendanceFactory   *AttendanceFactory
	auditConsumer       *audit.AuditClickHouseConsumer
	auditConsumerCancel context.CancelFunc

	// NEW: Audit Elasticsearch consumer
	auditESConsumer       *audit.AuditESConsumer
	auditESConsumerCancel context.CancelFunc

	// ==================== KYC ====================
	kycRepo    kycRepo.KYCDocumentRepository
	kycService kycSvc.KYCDocumentService
	kycHandler *kycHandler.KYCDocumentHandler
	storage    storage.Storage
	// =============================================

	// ==================== AVATAR ====================
	avatarRepo    avatarRepo.AvatarRepository
	avatarService avatarSvc.AvatarService
	avatarHandler *avatarHandler.AvatarHandler
	// ===============================================

	// 🆕 LOCATION ====================================
	locationRepo    postgres.LocationRepository
	locationService *service.LocationService
	locationHandler *locationhandler.LocationHandler
	// ================================================

	// 🆕 JOB =========================================
	jobRepo    postgres.JobRepository
	jobService *service.JobService
	jobHandler *handler.JobHandler
	// ================================================

	// 🆕 SUBSCRIPTION ====================================
	subscriptionPlanRepo        postgres.SubscriptionPlanRepository
	companyPaymentRepo          postgres.CompanyPaymentRepository
	subscriptionInvoiceRepo     postgres.SubscriptionInvoiceRepository
	subscriptionInvoiceItemRepo postgres.SubscriptionInvoiceItemRepository
	subscriptionReminderRepo    postgres.SubscriptionReminderRepository
	subscriptionPlanService     *service.SubscriptionPlanService
	paymentService              *service.PaymentService
	invoiceService              *service.SubscriptionInvoiceService
	reminderService             *service.ReminderService
	lifecycleService            *service.SubscriptionLifecycleService
	planHandler                 *handler.SubscriptionPlanHandler
	paymentHandler              *handler.PaymentHandler
	invoiceHandler              *handler.InvoiceHandler
	reminderHandler             *handler.ReminderHandler
	lifecycleHandler            *handler.SubscriptionLifecycleHandler
	// ===================================================
}

type KafkaLoggingManager struct {
	producer   *service.LogProducerService
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

	salesInfra := NewSalesInfraFactory(
		f.PostgresClient(),
		f.outboxRepo,
		f.idempotencyStore,
		f.GetAuditService(),
		f.EncryptionManager(),
		f.accountingInfra.TaxEngineService(),
		nil,
		f.logger,
	)
	f.salesInfra = salesInfra

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

	f.salesInfra.SetPlanItemUpdater(f.subscriptionInfra.PlanItemService())

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

	customerRepo := salesRepo.NewCustomerRepository(f.logger)
	subscriptionRepo := subRepo.NewSubscriptionRepository(f.logger)
	trialRepo := subRepo.NewTrialRepository(f.logger)
	subItemRepo := subRepo.NewSubscriptionItemRepository(f.logger)
	planItemRepo := subRepo.NewPlanItemRepository(f.logger)
	entitlementRepo := subRepo.NewEntitlementRepository(f.logger)
	usageRepo := subRepo.NewUsageRepository(f.logger)

	attendanceFactory.SetCustomerResolverDependencies(customerRepo, subscriptionRepo, trialRepo)

	usageSvc := usage_integration.NewUsageIntegrationService(
		f.PostgresClient().DB,
		subscriptionRepo,
		subItemRepo,
		planItemRepo,
		entitlementRepo,
		usageRepo,
		f.logger,
	)
	attendanceFactory.SetUsageIntegrationService(usageSvc)

	ctx := context.Background()
	f.attendanceFactory.StartBackgroundServices(ctx)

	kafkaLoggingMgr, err := f.InitializeKafkaLogging()
	if err != nil {
		logger.Error("failed to initialize Kafka logging", zap.Error(err))
	}
	f.kafkaLoggingMgr = kafkaLoggingMgr

	// Central outbox processor
	if f.kafkaProducer != nil {
		f.outboxProcessor = outbox.NewProcessor(
			f.outboxRepo,
			f.kafkaProducer,
			f.logger,
		)
		ctx, cancel := context.WithCancel(context.Background())
		f.outboxCancel = cancel
		go f.outboxProcessor.Start(ctx)
		f.logger.Info("Central outbox processor started – handles all domains")
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

	f.initializePayrollWorker()
	f.initializeResolverWorker() // 👈 ADD

	// Start Kafka consumers
	if f.kafkaProducer != nil && len(f.config.Kafka.Brokers) > 0 {
		// --- Existing consumers (analytics, student, accounting, inventory, sales, subscription) ---
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
			productSyncSvc := f.salesInfra.ProductSyncService()
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

		// ============================================================
		// AUDIT CLICKHOUSE CONSUMER
		// ============================================================
		auditTopic := "audit-logs"
		auditKafkaConsumer, err := client.NewKafkaConsumer(
			f.config,
			auditTopic,
			"audit-clickhouse-consumer-group",
			f.logger,
		)
		if err != nil {
			f.logger.Error("Failed to create audit Kafka consumer", zap.Error(err))
		} else {
			auditConsumer := audit.NewAuditClickHouseConsumer(
				auditKafkaConsumer,
				f.GetAuditClickHouseRepository(),
				f.logger,
				f.config.Kafka.Brokers,
			)
			f.auditConsumer = auditConsumer
			ctx, cancel := context.WithCancel(context.Background())
			f.auditConsumerCancel = cancel
			go func() {
				auditConsumer.Start(ctx)
				f.logger.Info("Audit ClickHouse consumer stopped")
			}()
			f.logger.Info("✅ Audit ClickHouse consumer started", zap.String("topic", auditTopic))
		}

		// ============================================================
		// NEW: AUDIT ELASTICSEARCH CONSUMER
		// ============================================================
		if f.config.Elasticsearch.URL != "" && f.esClient != nil {
			auditESConsumer, err := client.NewKafkaConsumer(
				f.config,
				"audit-logs",
				"audit-es-consumer-group", // separate group
				f.logger,
			)
			if err != nil {
				f.logger.Error("Failed to create audit ES Kafka consumer", zap.Error(err))
			} else {
				esConsumer := audit.NewAuditESConsumer(
					auditESConsumer,
					f.esClient,
					f.logger,
					f.config.Environment,
				)
				f.auditESConsumer = esConsumer
				ctx, cancel := context.WithCancel(context.Background())
				f.auditESConsumerCancel = cancel
				go func() {
					esConsumer.Start(ctx)
					f.logger.Info("Audit ES consumer stopped")
				}()
				f.logger.Info("✅ Audit ES consumer started", zap.String("topic", "audit-logs"))
			}
		} else {
			f.logger.Warn("Elasticsearch not available – audit ES consumer disabled")
		}
	} else {
		f.logger.Warn("Kafka not available – consumers disabled")
	}

	return f, nil
}

func (f *Factory) Close() error {
	f.closeOnce.Do(func() {
		close(f.closed)

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

		// Shutdown audit ClickHouse consumer
		if f.auditConsumerCancel != nil {
			f.logger.Info("Stopping audit ClickHouse consumer...")
			f.auditConsumerCancel()
		}
		if f.auditConsumer != nil {
			if err := f.auditConsumer.Close(); err != nil {
				f.logger.Error("Failed to close audit ClickHouse consumer", zap.Error(err))
			}
		}

		// NEW: Shutdown audit ES consumer
		if f.auditESConsumerCancel != nil {
			f.logger.Info("Stopping audit ES consumer...")
			f.auditESConsumerCancel()
		}
		if f.auditESConsumer != nil {
			if err := f.auditESConsumer.Close(); err != nil {
				f.logger.Error("Failed to close audit ES consumer", zap.Error(err))
			}
		}

		if f.payrollWorkerCancel != nil {
			f.logger.Info("Stopping payroll worker...")
			f.payrollWorkerCancel()
		}

		// 👈 ADD
		if f.resolverWorkerCancel != nil {
			f.logger.Info("Stopping leave resolver worker...")
			f.resolverWorkerCancel()
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

// AnalyticsCHRepo returns the ClickHouse analytics repository.
func (f *Factory) AnalyticsCHRepo() *clickhouse.AnalyticsRepository {
	if f.analyticsCHRepo == nil {
		f.analyticsCHRepo = clickhouse.NewAnalyticsRepository(f.clickhouseClient)
	}
	return f.analyticsCHRepo
}

// AnalyticsESRepo returns the Elasticsearch analytics repository.
func (f *Factory) AnalyticsESRepo() *elasticsearch.AnalyticsESRepository {
	if f.analyticsESRepo == nil {
		f.analyticsESRepo = elasticsearch.NewAnalyticsESRepository(f.esClient.Client, f.logger)
	}
	return f.analyticsESRepo
}

// AnalyticsService returns the analytics service.
func (f *Factory) AnalyticsService() *service.AnalyticsService {
	if f.analyticsService == nil {
		f.analyticsService = service.NewAnalyticsService(
			f.AnalyticsCHRepo(),
			f.AnalyticsESRepo(),
			f.clickhouseClient,
			f.esClient.Client,
			f.logger,
			f.GetCompanyService(), // optional, for multi-tenant validation
		)
	}
	return f.analyticsService
}

// AnalyticsHandler returns the analytics HTTP handler.
func (f *Factory) AnalyticsHandler() *handler.AnalyticsHandler {
	if f.analyticsHandler == nil {
		f.analyticsHandler = handler.NewAnalyticsHandler(
			f.AnalyticsService(),
			f.logger,
		)
	}
	return f.analyticsHandler
}

// ----------------------------------------------------------------------------
// All getters and helper methods
// ----------------------------------------------------------------------------

func (f *Factory) PayrollJobRepository() payrollrepo.PayrollJobRepository {
	if f.payrollJobRepo == nil {
		f.payrollJobRepo = payrollrepo.NewPayrollJobRepository(
			f.PostgresClient(),
		)
	}
	return f.payrollJobRepo
}

func (f *Factory) ComponentRepository() payrollrepo.ComponentRepository {
	if f.componentRepo == nil {
		f.componentRepo = payrollrepo.NewComponentRepository(
			f.PostgresClient(),
		)
	}
	return f.componentRepo
}

func (f *Factory) CompanySettingsRepository() payrollrepo.CompanySettingsRepository {
	if f.companySettingsRepo == nil {
		f.companySettingsRepo = payrollrepo.NewCompanySettingsRepository(
			f.PostgresClient(),
		)
	}
	return f.companySettingsRepo
}

func (f *Factory) ArrearsRepository() payrollrepo.ArrearsRepository {
	if f.arrearsRepo == nil {
		f.arrearsRepo = payrollrepo.NewArrearsRepository(
			f.PostgresClient(),
		)
	}
	return f.arrearsRepo
}

func (f *Factory) LoanRepository() payrollrepo.LoanRepository {
	if f.loanRepo == nil {
		f.loanRepo = payrollrepo.NewLoanRepository(
			f.PostgresClient(),
		)
	}
	return f.loanRepo
}

func (f *Factory) BankDetailsRepository() payrollrepo.BankDetailsRepository {
	if f.bankDetailsRepo == nil {
		f.bankDetailsRepo = payrollrepo.NewBankDetailsRepository(
			f.PostgresClient(),
			f.EncryptionManager(),
		)
	}
	return f.bankDetailsRepo
}

func (f *Factory) PayslipRepository() payrollrepo.PayslipRepository {
	if f.payslipRepo == nil {
		f.payslipRepo = payrollrepo.NewPayslipRepository(
			f.PostgresClient(),
		)
	}
	return f.payslipRepo
}

func (f *Factory) TaxDeclarationRepository() payrollrepo.TaxDeclarationRepository {
	if f.taxDeclarationRepo == nil {
		f.taxDeclarationRepo = payrollrepo.NewTaxDeclarationRepository(
			f.PostgresClient(),
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
			f.HREmployeeRepository(),
			f.idempotencyStore,
			f.GetAuditService(),
		)
	}
	return f.bankExportSvc
}
func (f *Factory) ComponentService() payrollsvc.ComponentService {
	if f.componentSvc == nil {
		f.componentSvc = payrollsvc.NewComponentService(
			f.ComponentRepository(),
			f.CompanySettingsRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
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
			f.HREmployeeRepository(),
			f.idempotencyStore,
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
			f.HREmployeeRepository(),
			f.emailSender,
			f.idempotencyStore,
			f.GetAuditService(),
		)
	}
	return f.payslipSvc
}
func (f *Factory) ReportingService() payrollsvc.ReportingService {
	if f.reportingSvc == nil {
		f.reportingSvc = payrollsvc.NewReportingService(
			f.PayrollRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
		)
	}
	return f.reportingSvc
}

func (f *Factory) TaxDeclarationService() payrollsvc.TaxDeclarationService {
	if f.taxDeclarationSvc == nil {
		f.taxDeclarationSvc = payrollsvc.NewTaxDeclarationService(
			f.TaxDeclarationRepository(),
			f.HREmployeeRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
		)
	}
	return f.taxDeclarationSvc
}
func (f *Factory) AttendanceRuleService() payrollsvc.AttendanceRuleService {
	if f.attendanceRuleSvc == nil {
		f.attendanceRuleSvc = payrollsvc.NewAttendanceRuleService(
			f.AttendanceRuleRepository(),
			f.ComponentRepository(),
			f.idempotencyStore,
			f.GetAuditService(),
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
			f.HREmployeeRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
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
			f.idempotencyStore, // ✅ position 7
			f.AttendanceRuleRepository(),
			f.EmployeeFineRepository(),
			f.ArrearsRepository(),
			f.LoanRepository(),
			f.ComponentRepository(),
			f.CompanySettingsRepository(),
			f.logger, // ✅ position 14
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
			f.HREmployeeRepository(),
			f.PDFGenerator(),
			f.GetAuditService(),
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
			f.HREmployeeRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
		)
	}
	return f.salaryStructureSvc
}

func (f *Factory) AttendanceRuleRepository() payrollrepo.AttendanceRuleRepository {
	if f.attendanceRuleRepo == nil {
		f.attendanceRuleRepo = payrollrepo.NewAttendanceRuleRepository(
			f.PostgresClient(),
		)
	}
	return f.attendanceRuleRepo
}

func (f *Factory) GetAttendanceRuleHandler() *payrollhandler.AttendanceRuleHandler {
	if f.attendanceRuleHandler == nil {
		f.attendanceRuleHandler = payrollhandler.NewAttendanceRuleHandler(
			f.AttendanceRuleService(),
		)
	}
	return f.attendanceRuleHandler
}

func (f *Factory) EmployeeFineRepository() payrollrepo.EmployeeFineRepository {
	if f.employeeFineRepo == nil {
		f.employeeFineRepo = payrollrepo.NewEmployeeFineRepository(
			f.PostgresClient(),
		)
	}
	return f.employeeFineRepo
}

func (f *Factory) GetEmployeeFineHandler() *payrollhandler.EmployeeFineHandler {
	if f.employeeFineHandler == nil {
		f.employeeFineHandler = payrollhandler.NewEmployeeFineHandler(
			f.EmployeeFineService(),
		)
	}
	return f.employeeFineHandler
}

func (f *Factory) CompensationRepository() payrollrepo.CompensationRepository {
	if f.compensationRepo == nil {
		f.compensationRepo = payrollrepo.NewCompensationRepository(
			f.PostgresClient(),
		)
	}
	return f.compensationRepo
}

func (f *Factory) SalaryStructureRepository() payrollrepo.SalaryStructureRepository {
	if f.salaryStructureRepo == nil {
		f.salaryStructureRepo = payrollrepo.NewSalaryStructureRepository(
			f.PostgresClient(),
		)
	}
	return f.salaryStructureRepo
}

func (f *Factory) StatutoryProfileRepository() payrollrepo.StatutoryProfileRepository {
	if f.statutoryProfileRepo == nil {
		f.statutoryProfileRepo = payrollrepo.NewStatutoryProfileRepository(
			f.PostgresClient(),
		)
	}
	return f.statutoryProfileRepo
}

func (f *Factory) StatutoryRepository() payrollrepo.StatutoryRepository {
	if f.statutoryRepo == nil {
		f.statutoryRepo = payrollrepo.NewStatutoryRepository(
			f.PostgresClient(),
		)
	}
	return f.statutoryRepo
}

func (f *Factory) PayrollRepository() payrollrepo.PayrollRepository {
	if f.payrollRepository == nil {
		f.payrollRepository = payrollrepo.NewPayrollRepository(
			f.PostgresClient(),
		)
	}
	return f.payrollRepository
}

func (f *Factory) CompensationService() payrollsvc.CompensationService {
	if f.compensationSvc == nil {
		f.compensationSvc = payrollsvc.NewCompensationService(
			f.CompensationRepository(),
			f.PayrollRepository(),
			f.HREmployeeRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
			f.logger,
		)
	}
	return f.compensationSvc
}
func (f *Factory) PayrollAdjustmentService() payrollsvc.PayrollAdjustmentService {
	if f.payrollAdjustmentSvc == nil {
		f.payrollAdjustmentSvc = payrollsvc.NewPayrollAdjustmentService(
			f.PayrollRepository(),
			f.HREmployeeRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
		)
	}
	return f.payrollAdjustmentSvc
}
func (f *Factory) PayrollLockService() payrollsvc.PayrollLockService {
	if f.payrollLockSvc == nil {
		f.payrollLockSvc = payrollsvc.NewPayrollLockService(
			f.PayrollRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
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
			f.HREmployeeRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
		)
	}
	return f.statutoryProfileSvc
}
func (f *Factory) StatutoryEngine() payrollsvc.StatutoryEngine {
	if f.statutoryEngineSvc == nil {
		f.statutoryEngineSvc = payrollsvc.NewStatutoryEngine(
			f.StatutoryRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
		)
	}
	return f.statutoryEngineSvc
}

func (f *Factory) GetCompensationHandler() *payrollhandler.CompensationHandler {
	if f.compensationHandler == nil {
		f.compensationHandler = payrollhandler.NewCompensationHandler(
			f.CompensationService(),
		)
	}
	return f.compensationHandler
}

func (f *Factory) GetPayrollAdjustmentHandler() *payrollhandler.PayrollAdjustmentHandler {
	if f.payrollAdjustmentHandler == nil {
		f.payrollAdjustmentHandler = payrollhandler.NewPayrollAdjustmentHandler(
			f.PayrollAdjustmentService(),
		)
	}
	return f.payrollAdjustmentHandler
}

func (f *Factory) GetPayrollLockHandler() *payrollhandler.PayrollLockHandler {
	if f.payrollLockHandler == nil {
		f.payrollLockHandler = payrollhandler.NewPayrollLockHandler(
			f.PayrollLockService(),
		)
	}
	return f.payrollLockHandler
}

func (f *Factory) GetPayrollCommandHandler() *payrollhandler.PayrollCommandHandler {
	if f.payrollCommandHandler == nil {
		f.payrollCommandHandler = payrollhandler.NewPayrollCommandHandler(
			f.PayrollEngineService(),
		)
	}
	return f.payrollCommandHandler
}

func (f *Factory) GetPayrollQueryHandler() *payrollhandler.PayrollQueryHandler {
	if f.payrollQueryHandler == nil {
		f.payrollQueryHandler = payrollhandler.NewPayrollQueryHandler(
			f.PayrollQueryService(),
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
		)
	}
	return f.payrollRunHandler
}

func (f *Factory) GetSalaryStructureHandler() *payrollhandler.SalaryStructureHandler {
	if f.salaryStructureHandler == nil {
		f.salaryStructureHandler = payrollhandler.NewSalaryStructureHandler(
			f.SalaryStructureService(),
		)
	}
	return f.salaryStructureHandler
}

func (f *Factory) GetStatutoryProfileHandler() *payrollhandler.StatutoryProfileHandler {
	if f.statutoryProfileHandler == nil {
		f.statutoryProfileHandler = payrollhandler.NewStatutoryProfileHandler(
			f.StatutoryProfileService(),
			f.StatutoryEngine(),
		)
	}
	return f.statutoryProfileHandler
}

func (f *Factory) GetBankExportHandler() *payrollhandler.BankExportHandler {
	if f.bankExportHandler == nil {
		f.bankExportHandler = payrollhandler.NewBankExportHandler(
			f.BankExportService(),
		)
	}
	return f.bankExportHandler
}

func (f *Factory) GetComponentHandler() *payrollhandler.ComponentHandler {
	if f.componentHandler == nil {
		f.componentHandler = payrollhandler.NewComponentHandler(
			f.ComponentService(),
		)
	}
	return f.componentHandler
}

func (f *Factory) GetLoanHandler() *payrollhandler.LoanHandler {
	if f.loanHandler == nil {
		f.loanHandler = payrollhandler.NewLoanHandler(
			f.LoanService(),
		)
	}
	return f.loanHandler
}

func (f *Factory) GetPayslipHandler() *payrollhandler.PayslipHandler {
	if f.payslipHandler == nil {
		f.payslipHandler = payrollhandler.NewPayslipHandler(
			f.PayslipService(),
		)
	}
	return f.payslipHandler
}

func (f *Factory) GetReportingHandler() *payrollhandler.ReportingHandler {
	if f.reportingHandler == nil {
		f.reportingHandler = payrollhandler.NewReportingHandler(
			f.ReportingService(),
		)
	}
	return f.reportingHandler
}

func (f *Factory) GetTaxDeclarationHandler() *payrollhandler.TaxDeclarationHandler {
	if f.taxDeclarationHandler == nil {
		f.taxDeclarationHandler = payrollhandler.NewTaxDeclarationHandler(
			f.TaxDeclarationService(),
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
	return hrservice.NewAttendancePayrollBridge(
		f.attendanceFactory.SummaryRepository(),
		f.attendanceFactory.EventRepository(),
		f.GetAuditService(),
		f.idempotencyStore,
	)
}

// ----- Legacy HR repositories (kept) -----

func (f *Factory) HREmployeeRepository() hrpostgres.EmployeeRepository {
	if f.hrEmployeeRepository == nil {
		f.hrEmployeeRepository = hrpostgres.NewEmployeeRepository(
			f.PostgresClient(),
		)
	}
	return f.hrEmployeeRepository
}

func (f *Factory) OrgUnitRepository() hrpostgres.OrgUnitRepository {
	if f.orgUnitRepository == nil {
		f.orgUnitRepository = hrpostgres.NewOrgUnitRepository(
			f.PostgresClient(),
		)
	}
	return f.orgUnitRepository
}

func (f *Factory) LeaveRepository() leaverepo.LeaveRepository {
	if f.leaveRepository == nil {
		f.leaveRepository = leaverepo.NewLeaveRepository(
			f.PostgresClient(),
		)
	}
	return f.leaveRepository
}

// 👈 ADD — placed next to LeaveRepository()
func (f *Factory) ResolverJobRepository() leaverepo.ResolverJobRepository {
	if f.resolverJobRepo == nil {
		f.resolverJobRepo = leaverepo.NewResolverJobRepository(f.PostgresClient())
	}
	return f.resolverJobRepo
}

// ----- Services -----

func (f *Factory) GetEmployeeService() *hrservice.EmployeeService {
	if f.employeeService == nil {
		f.employeeService = hrservice.NewEmployeeService(
			f.HREmployeeRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
			hrservice.EmployeeServiceConfig{
				MaxDocumentSizeMB: f.config.HR.Documents.MaxSizeMB,
				DocumentStorage:   f.DocumentStorage(),
				EncryptionMgr:     f.EncryptionManager(),
			},
			f.PostgresClient(),        // 👈 ADD
			f.ResolverJobRepository(), // 👈 ADD
		)
	}
	return f.employeeService
}
func (f *Factory) GetEmployeeQueryService() *hrservice.EmployeeQueryService {
	if f.employeeQueryService == nil {
		f.employeeQueryService = hrservice.NewEmployeeQueryService(
			f.HREmployeeRepository(),
			f.DocumentStorage(),
			f.GetAuditService(),
			f.EncryptionManager(), // 👈 ADD THIS LINE (fixes the compiler error)
		)
	}
	return f.employeeQueryService
}

func (f *Factory) GetOrgUnitService() *hrservice.OrgUnitService {
	if f.orgUnitService == nil {
		f.orgUnitService = hrservice.NewOrgUnitService(
			f.PostgresClient(),     // ✅
			f.OrgUnitRepository(),  // ✅
			f.LocationRepository(), // ✅ NEW — added
			f.GetAuditService(),
			f.idempotencyStore,
		)
	}
	return f.orgUnitService
}
func (f *Factory) GetOrgUnitQueryService() *hrservice.OrgUnitQueryService {
	if f.orgUnitQueryService == nil {
		f.orgUnitQueryService = hrservice.NewOrgUnitQueryService(
			f.PostgresClient(), // ✅ FIX

			f.OrgUnitRepository(),
			f.GetAuditService(),
		)
	}
	return f.orgUnitQueryService
}

func (f *Factory) GetAuditService() *audit.AuditService {
	if f.auditService == nil {
		f.auditService = audit.NewAuditService(f.outboxRepo, f.PostgresClient(), f.logger)
	}
	return f.auditService
}
func (f *Factory) GetAuditClickHouseRepository() audit.AuditRepository {
	if f.auditRepository == nil {
		f.auditRepository = audit.NewAuditRepositoryClickHouse(f.clickhouseClient, f.logger)
	}
	return f.auditRepository
}
func (f *Factory) GetAuditQueryService() *audit.AuditQueryService {
	if f.auditQueryService == nil {
		chRepo := f.GetAuditClickHouseRepository()
		f.auditQueryService = audit.NewAuditQueryService(chRepo, f.logger)
	}
	return f.auditQueryService
}

// ----- Leave -----

func (f *Factory) LeavePolicyService() leavesvc.LeavePolicyService {
	if f.leavePolicyService == nil {
		f.leavePolicyService = leavesvc.NewLeavePolicyService(
			f.LeaveRepository(),
			f.idempotencyStore,
			f.GetAuditService(),
		)
	}
	return f.leavePolicyService
}

func (f *Factory) LeavePolicyConfigService() leavesvc.LeavePolicyConfigService {
	if f.leavePolicyConfigService == nil {
		f.leavePolicyConfigService = leavesvc.NewLeavePolicyConfigService(
			f.LeaveRepository(),
			f.idempotencyStore,
			f.GetAuditService(),
			f.PostgresClient(),        // 👈 ADD
			f.ResolverJobRepository(), // 👈 ADD
		)
	}
	return f.leavePolicyConfigService
}

func (f *Factory) LeaveAccrualService() leavesvc.LeaveAccrualService {
	if f.leaveAccrualService == nil {
		f.leaveAccrualService = leavesvc.NewLeaveAccrualService(
			f.LeaveRepository(),
			f.idempotencyStore,
			f.GetAuditService(),
		)
	}
	return f.leaveAccrualService
}

func (f *Factory) LeaveQueryService() leavesvc.LeaveQueryService {
	if f.leaveQueryService == nil {
		f.leaveQueryService = leavesvc.NewLeaveQueryService(
			f.LeaveRepository(),
			f.HREmployeeRepository(),
			f.GetAuditService(),
		)
	}
	return f.leaveQueryService
}

func (f *Factory) LeaveBalanceService() leavesvc.LeaveBalanceService {
	if f.leaveBalanceService == nil {
		f.leaveBalanceService = leavesvc.NewLeaveBalanceService(
			f.LeaveRepository(),
			f.idempotencyStore,
			f.GetAuditService(),
		)
	}
	return f.leaveBalanceService
}

func (f *Factory) LeaveRequestService() leavesvc.LeaveRequestService {
	if f.leaveRequestService == nil {
		f.leaveRequestService = leavesvc.NewLeaveRequestService(
			f.LeaveRepository(),
			f.HREmployeeRepository(),
			f.LeaveBalanceService(),
			f.idempotencyStore,
			f.GetAuditService(),
		)
	}
	return f.leaveRequestService
}

func (f *Factory) GetLeavePolicyResolutionService() leavesvc.LeavePolicyResolutionService {
	if f.leavePolicyResolutionService == nil {
		f.leavePolicyResolutionService = leavesvc.NewLeavePolicyResolutionService(
			f.LeaveRepository(),
			f.ResolverJobRepository(), // ← NEW
			f.PostgresClient(),        // ← NEW

			f.idempotencyStore,
			f.GetAuditService(),
		)
	}
	return f.leavePolicyResolutionService
}

func (f *Factory) GetLeavePolicyResolutionHandler() *leavehandler.LeavePolicyResolutionHandler {
	if f.leavePolicyResolutionHandler == nil {
		f.leavePolicyResolutionHandler = leavehandler.NewLeavePolicyResolutionHandler(
			f.GetLeavePolicyResolutionService(),
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
		)
	}
	return f.leaveAdminHandler
}

func (f *Factory) LeaveQueryHandler() *leavehandler.LeaveQueryHandler {
	if f.leaveQueryHandler == nil {
		f.leaveQueryHandler = leavehandler.NewLeaveQueryHandler(
			f.LeaveQueryService(),
		)
	}
	return f.leaveQueryHandler
}

func (f *Factory) LeaveRequestHandler() *leavehandler.LeaveRequestHandler {
	if f.leaveRequestHandler == nil {
		f.leaveRequestHandler = leavehandler.NewLeaveRequestHandler(
			f.LeaveRequestService(),
			f.LeaveQueryService(),
			f.attendanceFactory.SchedulingService(),
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

// 👈 ADD — placed next to initializePayrollWorker
func (f *Factory) initializeResolverWorker() {
	if f.resolverWorker != nil {
		return
	}
	interval := 30 * time.Second
	if !f.config.IsProduction() {
		interval = 5 * time.Second
	}
	f.resolverWorker = leaveworker.NewResolverWorker(
		f.ResolverJobRepository(),
		f.GetLeavePolicyResolutionService(),
		f.logger,
		interval,
	)
	ctx, cancel := context.WithCancel(context.Background())
	f.resolverWorkerCancel = cancel
	go f.resolverWorker.Start(ctx)
	f.logger.Info("leave resolver worker started", zap.Duration("interval", interval))
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
		zap.Bool("es_enabled", false),
		zap.Bool("ch_enabled", mgr.chConsumer != nil),
	)
	return mgr, nil
}

// ----- Repository getters -----

func (f *Factory) AdminDeviceRepository() *scylla.AdminDeviceRepositoryImpl {
	if f.adminDeviceRepo == nil {
		f.adminDeviceRepo = scylla.NewAdminDeviceRepository(
			f.ScyllaClient(),
		)
	}
	return f.adminDeviceRepo
}

func (f *Factory) AdminDeviceTrustRepository() scylla.AdminDeviceTrustRepository {
	if f.adminDeviceTrustRepo == nil {
		f.adminDeviceTrustRepo = scylla.NewAdminDeviceTrustRepository(
			f.ScyllaClient(),
		)
	}
	return f.adminDeviceTrustRepo
}

func (f *Factory) AdminMPINRepository() *scylla.AdminMPINRepositoryImpl {
	if f.adminMPINRepo == nil {
		f.adminMPINRepo = scylla.NewAdminMPINRepository(
			f.ScyllaClient(),
		)
	}
	return f.adminMPINRepo
}

func (f *Factory) AdminDeviceHistoryRepository() *scylla.AdminDeviceHistoryRepositoryImpl {
	if f.adminDeviceHistoryRepo == nil {
		f.adminDeviceHistoryRepo = scylla.NewAdminDeviceHistoryRepository(
			f.ScyllaClient(),
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
		)
	}
	return f.postgresUserRepository
}

func (f *Factory) CompanyRepository() postgres.CompanyRepository {
	if f.postgresCompanyRepository == nil {
		f.postgresCompanyRepository = postgres.NewCompanyRepository(
			f.PostgresClient(),
		)
	}
	return f.postgresCompanyRepository
}

// 🆕 JOB REPOSITORY =============================================
// Reuses the same CompanyRepositoryImpl concrete type (see postgres package).
func (f *Factory) JobRepository() postgres.JobRepository {
	if f.jobRepo == nil {
		f.jobRepo = postgres.NewJobRepository(f.PostgresClient())
	}
	return f.jobRepo
}

// 🆕 JOB SERVICE ================================================
func (f *Factory) JobService() *service.JobService {
	if f.jobService == nil {
		f.jobService = service.NewJobService(
			f.PostgresClient(),
			f.JobRepository(),
			f.CompanyRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
		)
	}
	return f.jobService
}

// 🆕 JOB HANDLER ================================================
func (f *Factory) JobHandler() *handler.JobHandler {
	if f.jobHandler == nil {
		f.jobHandler = handler.NewJobHandler(
			f.JobService(),
			f.GetCompanyService(),
		)
	}
	return f.jobHandler
}

// ================================================================

func (f *Factory) PepperStoreRepository() pepperstore.PepperStore {
	if f.pepperStoreRepo == nil {
		f.pepperStoreRepo = scylla.NewPepperStoreRepository(
			f.ScyllaClient(),
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
		)
	}
	return f.otpRepository
}

func (f *Factory) MPINRepository() scylla.MPINRepository {
	if f.mpinRepository == nil {
		f.mpinRepository = scylla.NewMPINRepository(
			f.ScyllaClient(),
		)
	}
	return f.mpinRepository
}

func (f *Factory) GetDeviceTrustRepository() scylla.DeviceTrustRepository {
	if f.deviceTrustRepo == nil {
		f.deviceTrustRepo = scylla.NewDeviceTrustRepository(f.scyllaClient)
	}
	return f.deviceTrustRepo
}

func (f *Factory) SessionRepository() redis.SessionRepository {
	if f.sessionRepo == nil {
		f.sessionRepo = redis.NewSessionRepository(
			f.redisClient.Client(),
		)
	}
	return f.sessionRepo
}

func (f *Factory) DeviceRepository() scylla.DeviceRepository {
	if f.deviceRepository == nil {
		f.deviceRepository = scylla.NewDeviceRepository(
			f.ScyllaClient(),
		)
	}
	return f.deviceRepository
}

func (f *Factory) GetDeviceHistoryRepository() *scylla.DeviceHistoryRepositoryImpl {
	if f.deviceHistoryRepo == nil {
		f.deviceHistoryRepo = scylla.NewDeviceHistoryRepository(
			f.ScyllaClient(),
		)
	}
	return f.deviceHistoryRepo
}

func (f *Factory) AdminRepository() postgres.AdminRepository {
	if f.adminRepository == nil {
		f.adminRepository = postgres.NewAdminRepositoryPostgres(
			f.PostgresClient(),
		)
	}
	return f.adminRepository
}

// ============================================================
// ✅ FIX #1 — NewJWTService now takes *client.PostgresClient first
// ============================================================
func (f *Factory) GetJWTService() *service.JWTService {
	if f.jwtService == nil {
		f.jwtService = service.NewJWTService(
			f.PostgresClient(), // ✅ FIX #1
			f.Config(),
			f.CompanyRepository(),
			f.AdminRepository(),
			f.GetAuditService(),
			f.LocationRepository(),
		)
	}
	return f.jwtService
}

func (f *Factory) GetRBACInitService() *service.RBACInitService {
	if f.rbacInitService == nil {
		f.rbacInitService = service.NewRBACInitService(
			f.CompanyRepository(),
		)
	}
	return f.rbacInitService
}

func (f *Factory) ServiceFactory() *service.ServiceFactory {
	if f.serviceFactory == nil {
		f.serviceFactory = service.NewServiceFactory(
			f.PostgresClient(), // ← new first arg
			f.UserRepository(),
			f.Hasher(),
			f.EncryptionManager(),
			f.GetAuditService(),
			f.idempotencyStore,
		)
	}
	return f.serviceFactory
}

func (f *Factory) GetUserService() *service.UserService {
	f.once.Do(func() {
		repo := f.UserRepository()
		hasher := f.Hasher()
		encMgr := f.EncryptionManager()
		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), f.logger)
		}
		f.userService = service.NewUserServiceWithCache(
			f.PostgresClient(), // ← new first arg
			repo, hasher, encMgr, distCache,
			f.GetAuditService(),
			f.idempotencyStore,
		)
	})
	return f.userService
}

func (f *Factory) GetPhoneValidator() *service.PhoneValidatorImpl {
	phoneValidator := service.NewPhoneValidator(
		f.GetUserService(),
		nil,
		f.GetAuditService(),
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
			logProducer,
			f.GetAuditService(),
			f.idempotencyStore,
			phoneValidator,
			f.AdminDeviceTrustRepository(),
			f.GetAdminDeviceService(),
			f.smsManager,
		)

		if phoneValidator != nil {
			phoneValidator.SetAdminService(f.GetAdminService())
		}
	}
	return f.otpService
}

// ============================================================
// ✅ FIX #2 — NewAdminService now takes *client.PostgresClient
//
//	right after CompanyRepository
//
// ============================================================
func (f *Factory) GetAdminService() *service.AdminService {
	if f.adminService == nil {
		f.adminService = service.NewAdminService(
			f.AdminRepository(),
			f.CompanyRepository(),
			f.PostgresClient(), // ✅ FIX #2
			f.GetSessionService(),
			f.GetOTPService(),
			f.GetMPINService(),
			f.GetDeviceService(),
			f.Hasher(),
			f.EncryptionManager(),
			f.GetAuditService(),
			f.idempotencyStore,
		)
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
			f.PostgresClient(), // ← new first arg
			mpinRepo,
			userRepo,
			deviceTrustRepo,
			userOTPService,
			encryptionMgr,
			hasher,
			cfg,
			logProducer,
			f.GetAuditService(),
			f.idempotencyStore,
		)
		if distCache != nil {
			f.mpinService.SetDistributedCache(distCache)
		}
	}
	return f.mpinService
}

// ============================================================
// ✅ FIX #3 — NewSessionService now takes *client.PostgresClient
//
//	as the final argument
//
// ============================================================
func (f *Factory) GetSessionService() *service.SessionService {
	if f.sessionService == nil {
		sessionRepo := f.SessionRepository()
		cfg := f.Config()
		jwtService := f.GetJWTService()
		companyRepo := f.CompanyRepository()
		f.sessionService = service.NewSessionService(
			sessionRepo,
			cfg,
			jwtService,
			companyRepo,
			f.GetAuditService(),
			f.LocationRepository(),
			f.PostgresClient(), // ✅ FIX #3
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
			f.GetAuditService(),
			f.idempotencyStore,
			f.GetLogProducerService(),
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

// ============================================================
// ✅ FIX #4 — NewCompanyService now takes *client.PostgresClient
//
//	as the first argument
//
// ============================================================
func (f *Factory) GetCompanyService() *service.CompanyService {
	if f.companyService == nil {
		f.companyService = service.NewCompanyService(
			f.PostgresClient(),
			f.CompanyRepository(),
			f.LocationRepository(),
			f.LocationService(),                        // 👈 ADD — locationService
			f.attendanceFactory.WorkCenterRepository(), // 👈 ADD — workCenterRepo (Case A: reuse AttendanceFactory instance)
			f.HREmployeeRepository(),
			f.GetEmployeeService(),
			f.GetUserService(),
			f.SubscriptionPlanService(),
			f.PaymentService(),
			f.InvoiceService(),
			f.ReminderService(),
			f.LifecycleService(),
			f.GetAuditService(),
			f.idempotencyStore,
			*f.config,
			f.RedisClient().Client(),
			f.ResolverJobRepository(),
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
			f.idempotencyStore,
			f.GetAuditService(),
			*cfg,
		)

		historyRepo := f.AdminDeviceHistoryRepository()
		f.adminDeviceService.SetHistoryRepository(historyRepo)
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
		logProducer := f.GetLogProducerService()

		f.adminMPINService = service.NewAdminMPINService(
			mpinRepo,
			adminRepo,
			deviceTrustRepo,
			otpService,
			encryptionMgr,
			hasher,
			cfg,
			logProducer,
			f.idempotencyStore,
			f.GetAuditService(),
		)

		if f.redisClient != nil {
			distCache := service.NewDistributedCache(f.redisClient.Client(), f.logger)
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
			logProducer,
			phoneValidator,
			deviceTrustRepo,
			f.GetDeviceService(),
			smsManager,
			f.GetAuditService(),
			f.idempotencyStore,
		)
	}
	return f.userOTPService
}

func (f *Factory) GetPairingRepository() redis.PairingRepository {
	if f.pairingRepo == nil {
		f.pairingRepo = redis.NewPairingRepository(
			f.redisClient.Client(),
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
			f.GetAuditService(),
			f.idempotencyStore,
			f.GetCompanyService(),
		)
	}
	return f.pairingService
}

func (f *Factory) GetWebSocketService() *service.WebSocketService {
	if f.wsService == nil {
		f.wsService = service.NewWebSocketService()
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
		)
	}
	return f.pairingHandler
}

func (f *Factory) GetWebSocketHandler() *handler.WebSocketHandler {
	if f.wsHandler == nil {
		f.wsHandler = handler.NewWebSocketHandler(
			f.GetWebSocketService(),
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
	if sc, err := scylla.NewScyllaClient(f.config); err != nil {
		initErrors = append(initErrors, fmt.Errorf("scylla: %w", err))
	} else {
		f.scyllaClient = sc
		if err := f.scyllaClient.HealthCheck(ctx); err != nil {
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

// ==================== STORAGE GETTER ====================

func (f *Factory) Storage() storage.Storage {
	if f.storage == nil {
		basePath := "/data"

		baseURL := f.config.Server.PublicBaseURL
		if baseURL == "" {
			baseURL = fmt.Sprintf("http://localhost:%d/api/v1", f.config.Server.Port)
			if f.config.Server.EnableTLS {
				baseURL = fmt.Sprintf("https://localhost:%d/api/v1", f.config.Server.Port)
			}
		} else {
			baseURL = strings.TrimSuffix(baseURL, "/admin")
			baseURL = strings.TrimSuffix(baseURL, "/admin/")
			baseURL = strings.TrimSuffix(baseURL, "/")
		}

		f.storage = storage.NewLocalStorage(basePath, baseURL)
		f.logger.Info("Local storage initialized",
			zap.String("base_path", basePath),
			zap.String("base_url", baseURL),
		)
	}
	return f.storage
}

// ==================== KYC GETTERS ====================

func (f *Factory) KYCDocumentRepository() kycRepo.KYCDocumentRepository {
	if f.kycRepo == nil {
		f.kycRepo = kycRepo.NewKYCDocumentRepository(f.logger)
	}
	return f.kycRepo
}

func (f *Factory) KYCDocumentService() kycSvc.KYCDocumentService {
	if f.kycService == nil {
		f.kycService = kycSvc.NewKYCDocumentService(
			f.KYCDocumentRepository(),
			f.idempotencyStore,
			f.GetAuditService(),
			f.PostgresClient(),
			f.Storage(),
			f.logger,
		)
	}
	return f.kycService
}

func (f *Factory) KYCDocumentHandler() *kycHandler.KYCDocumentHandler {
	if f.kycHandler == nil {
		f.kycHandler = kycHandler.NewKYCDocumentHandler(
			f.KYCDocumentService(),
			f.Storage(),
			f.logger,
		)
	}
	return f.kycHandler
}

// ==================== END KYC GETTERS ====================

// ==================== AVATAR GETTERS ====================

func (f *Factory) AvatarRepository() avatarRepo.AvatarRepository {
	if f.avatarRepo == nil {
		f.avatarRepo = avatarRepo.NewAvatarRepository(f.logger)
	}
	return f.avatarRepo
}

func (f *Factory) AvatarService() avatarSvc.AvatarService {
	if f.avatarService == nil {
		f.avatarService = avatarSvc.NewAvatarService(
			f.AvatarRepository(),
			f.Storage(),
			f.PostgresClient(),
			f.idempotencyStore,
			f.GetAuditService(),
			f.config,
			f.logger,
		)
	}
	return f.avatarService
}

func (f *Factory) AvatarHandler() *avatarHandler.AvatarHandler {
	if f.avatarHandler == nil {
		f.avatarHandler = avatarHandler.NewAvatarHandler(
			f.AvatarService(),
			f.Storage(),
			f.config,
			f.logger,
		)
	}
	return f.avatarHandler
}

// ==================== END AVATAR GETTERS ====================

// 🆕 LOCATION GETTERS ========================================

// LocationRepository returns the location repository.
func (f *Factory) LocationRepository() postgres.LocationRepository {
	if f.locationRepo == nil {
		f.locationRepo = postgres.NewLocationRepository(f.PostgresClient())
	}
	return f.locationRepo
}

// ============================================================
// ✅ FIX #5 — NewLocationService now takes *client.PostgresClient
//
//	as the first argument
//
// ============================================================
func (f *Factory) LocationService() *service.LocationService {
	if f.locationService == nil {
		cfg := service.DefaultLocationConfig()
		f.locationService = service.NewLocationService(
			f.PostgresClient(), // ✅ FIX #5
			f.LocationRepository(),
			f.CompanyRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
			&cfg,
			f.RedisClient().Client(),
		)
	}
	return f.locationService
}

// LocationHandler returns the location HTTP handler.
func (f *Factory) LocationHandler() *locationhandler.LocationHandler {
	if f.locationHandler == nil {
		f.locationHandler = locationhandler.NewLocationHandler(
			f.LocationService(),
		)
	}
	return f.locationHandler
}

// ============================================================

// 🆕 SUBSCRIPTION GETTERS =====================================

// SubscriptionPlanRepository returns the subscription plan repository.
func (f *Factory) SubscriptionPlanRepository() postgres.SubscriptionPlanRepository {
	if f.subscriptionPlanRepo == nil {
		f.subscriptionPlanRepo = postgres.NewSubscriptionPlanRepository(f.PostgresClient())
	}
	return f.subscriptionPlanRepo
}

// CompanyPaymentRepository returns the company payment repository.
func (f *Factory) CompanyPaymentRepository() postgres.CompanyPaymentRepository {
	if f.companyPaymentRepo == nil {
		f.companyPaymentRepo = postgres.NewCompanyPaymentRepository(f.PostgresClient())
	}
	return f.companyPaymentRepo
}

// SubscriptionInvoiceRepository returns the subscription invoice repository.
func (f *Factory) SubscriptionInvoiceRepository() postgres.SubscriptionInvoiceRepository {
	if f.subscriptionInvoiceRepo == nil {
		f.subscriptionInvoiceRepo = postgres.NewSubscriptionInvoiceRepository(f.PostgresClient())
	}
	return f.subscriptionInvoiceRepo
}

// SubscriptionInvoiceItemRepository returns the invoice item repository.
func (f *Factory) SubscriptionInvoiceItemRepository() postgres.SubscriptionInvoiceItemRepository {
	if f.subscriptionInvoiceItemRepo == nil {
		f.subscriptionInvoiceItemRepo = postgres.NewSubscriptionInvoiceItemRepository(f.PostgresClient())
	}
	return f.subscriptionInvoiceItemRepo
}

// SubscriptionReminderRepository returns the reminder repository.
func (f *Factory) SubscriptionReminderRepository() postgres.SubscriptionReminderRepository {
	if f.subscriptionReminderRepo == nil {
		f.subscriptionReminderRepo = postgres.NewSubscriptionReminderRepository(f.PostgresClient())
	}
	return f.subscriptionReminderRepo
}

// SubscriptionPlanService returns the subscription plan service.
func (f *Factory) SubscriptionPlanService() *service.SubscriptionPlanService {
	if f.subscriptionPlanService == nil {
		f.subscriptionPlanService = service.NewSubscriptionPlanService(
			f.SubscriptionPlanRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
			nil, // use defaults
		)
	}
	return f.subscriptionPlanService
}

// InvoiceService returns the subscription invoice service.
func (f *Factory) InvoiceService() *service.SubscriptionInvoiceService {
	if f.invoiceService == nil {
		cfg := service.DefaultInvoiceConfig()
		f.invoiceService = service.NewSubscriptionInvoiceService(
			f.SubscriptionInvoiceRepository(),
			f.SubscriptionInvoiceItemRepository(),
			f.CompanyRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
			&cfg,
		)
	}
	return f.invoiceService
}

// PaymentService returns the payment service.
func (f *Factory) PaymentService() *service.PaymentService {
	if f.paymentService == nil {
		cfg := service.DefaultPaymentConfig()
		f.paymentService = service.NewPaymentService(
			f.CompanyPaymentRepository(),
			f.CompanyRepository(),
			f.SubscriptionPlanRepository(),
			f.InvoiceService(),
			f.GetAuditService(),
			f.idempotencyStore,
			f.PostgresClient(),
			&cfg,
		)
	}
	return f.paymentService
}

// ReminderService returns the reminder service.
func (f *Factory) ReminderService() *service.ReminderService {
	if f.reminderService == nil {
		cfg := service.DefaultReminderConfig()
		var notificationSender service.NotificationSender
		f.reminderService = service.NewReminderService(
			f.SubscriptionReminderRepository(),
			f.CompanyRepository(),
			f.GetUserService(),
			notificationSender,
			f.GetAuditService(),
			f.idempotencyStore,
			f.PostgresClient(),
			&cfg,
		)
	}
	return f.reminderService
}

// LifecycleService returns the subscription lifecycle service.
func (f *Factory) LifecycleService() *service.SubscriptionLifecycleService {
	if f.lifecycleService == nil {
		cfg := service.DefaultLifecycleConfig()
		f.lifecycleService = service.NewSubscriptionLifecycleService(
			f.PostgresClient(),
			f.CompanyRepository(),
			f.GetAuditService(),
			f.idempotencyStore,
			&cfg,
		)
	}
	return f.lifecycleService
}

// SubscriptionPlanHandler returns the subscription plan HTTP handler.
func (f *Factory) SubscriptionPlanHandler() *handler.SubscriptionPlanHandler {
	if f.planHandler == nil {
		f.planHandler = handler.NewSubscriptionPlanHandler(
			f.SubscriptionPlanService(),
			f.idempotencyStore,
		)
	}
	return f.planHandler
}

// PaymentHandler returns the payment HTTP handler.
func (f *Factory) PaymentHandler() *handler.PaymentHandler {
	if f.paymentHandler == nil {
		f.paymentHandler = handler.NewPaymentHandler(
			f.PaymentService(),
			f.idempotencyStore,
		)
	}
	return f.paymentHandler
}

// InvoiceHandler returns the invoice HTTP handler.
func (f *Factory) InvoiceHandler() *handler.InvoiceHandler {
	if f.invoiceHandler == nil {
		f.invoiceHandler = handler.NewInvoiceHandler(
			f.InvoiceService(),
			f.idempotencyStore,
		)
	}
	return f.invoiceHandler
}

// ReminderHandler returns the reminder HTTP handler.
func (f *Factory) ReminderHandler() *handler.ReminderHandler {
	if f.reminderHandler == nil {
		f.reminderHandler = handler.NewReminderHandler(
			f.ReminderService(),
			f.idempotencyStore,
		)
	}
	return f.reminderHandler
}

// LifecycleHandler returns the lifecycle HTTP handler.
func (f *Factory) LifecycleHandler() *handler.SubscriptionLifecycleHandler {
	if f.lifecycleHandler == nil {
		f.lifecycleHandler = handler.NewSubscriptionLifecycleHandler(
			f.LifecycleService(),
			f.idempotencyStore,
		)
	}
	return f.lifecycleHandler
}

// ============================================================

// InitializeHandlers – updated to include KYC, avatar, location, job and subscription handlers.
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

	otpHandler := handler.NewOTPHandler(
		otpService,
		sessionService,
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
	)
	rbacHandler := handler.NewRBACHandler(
		companyService,
		userService,
		f.GetAuditService(),
		f.idempotencyStore,
	)
	authHandler := handler.NewAuthHandler(
		userOTPService,
		mpinService,
		sessionService,
		userService,
		companyService,
		deviceService,
		jwtService,
	)
	f.authHandler = authHandler

	pairingHandler := f.GetPairingHandler()
	wsHandler := f.GetWebSocketHandler()

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
		CostCenterHandler:         f.accountingInfra.CostCenterHandler(), // 👈 ADD
	}
	inventoryHandlers := f.GetInventoryHandlers()

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

	var subscriptionHandlers *subscription.SubscriptionHandlers
	if f.subscriptionInfra != nil {
		subscriptionHandlers = f.subscriptionInfra.SubscriptionHandlers()
	} else {
		logger.Warn("Subscription infra not available – subscription routes will not be registered")
	}

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

	leavePolicyResolutionHandler := f.GetLeavePolicyResolutionHandler()
	orgUnitHandler := f.GetOrgUnitHandler()
	employeeHandler := f.GetHREmployeeHandler()
	leaveAdminHandler := f.LeaveAdminHandler()
	leaveRequestHandler := f.LeaveRequestHandler()
	leaveQueryHandler := f.LeaveQueryHandler()

	kycHandler := f.KYCDocumentHandler()
	avatarHandler := f.AvatarHandler()
	locationHandler := f.LocationHandler()

	// 🆕 JOB HANDLER ============================================
	jobHandler := f.JobHandler()
	// ===========================================================

	planHandler := f.SubscriptionPlanHandler()
	paymentHandler := f.PaymentHandler()
	invoiceHandler := f.InvoiceHandler()
	reminderHandler := f.ReminderHandler()
	lifecycleHandler := f.LifecycleHandler()

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
		subscriptionHandlers,
		kycHandler,
		avatarHandler,
		locationHandler,
		planHandler,
		paymentHandler,
		invoiceHandler,
		reminderHandler,
		lifecycleHandler,
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
		f.AnalyticsHandler(),
		f.LocationService(),
		companyService,
		jobHandler, // 🆕 JOB HANDLER — final argument
	)

	logger.Info("Handlers and router initialized with JWT, bitmask, QR web login, attendance, leave, payroll, biometric, accounting, inventory, subscription, sales, KYC, avatar, location, job and subscription lifecycle systems")
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
		)
	}
	return f.postgresUserRepository
}
func (f *Factory) PostgresCompanyRepository() postgres.CompanyRepository {
	if f.postgresCompanyRepository == nil {
		f.postgresCompanyRepository = postgres.NewCompanyRepository(
			f.PostgresClient(),
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
			f.GetCompanyService(), // 👈 ADD — CompanyService
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
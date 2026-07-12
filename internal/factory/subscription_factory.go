// internal/factory/subscription_factory.go
package factory

import (
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	salesService "auth-service/internal/sales/service"
	router "auth-service/internal/subscription" // <-- import the subscription package
	"auth-service/internal/subscription/handler"
	"auth-service/internal/subscription/repository"
	"auth-service/internal/subscription/service"
)

// SubscriptionInfraFactory manages lazy initialisation of all subscription components.
type SubscriptionInfraFactory struct {
	logger           *zap.Logger
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService

	// external services provided by other modules
	pricingService        salesService.PricingService
	couponService         salesService.CouponService
	discountEngineService salesService.DiscountEngineService
	taxIntegrationService salesService.TaxIntegrationService
	invoiceService        salesService.InvoiceService

	// repositories
	addonRepo           repository.AddonRepository
	analyticsRepo       repository.AnalyticsRepository
	benefitRepo         repository.BenefitRepository
	billingPolicyRepo   repository.BillingPolicyRepository
	entitlementRepo     repository.EntitlementRepository
	featureRepo         repository.FeatureRepository
	lookupRepo          repository.LookupRepository
	pausePolicyRepo     repository.PausePolicyRepository
	planItemRepo        repository.PlanItemRepository
	planRepo            repository.PlanRepository
	prorationPolicyRepo repository.ProrationPolicyRepository
	renewalPolicyRepo   repository.RenewalPolicyRepository
	subItemRepo         repository.SubscriptionItemRepository
	subRepo             repository.SubscriptionRepository
	timelineRepo        repository.TimelineRepository
	trialRepo           repository.TrialRepository
	usageRepo           repository.UsageRepository
	versionRepo         repository.VersionRepository

	// services
	addonService           service.AddonService
	analyticsQueryService  service.AnalyticsQueryService
	analyticsService       service.SubscriptionAnalyticsService
	benefitService         service.BenefitService
	billingEngineService   *service.BillingEngineService
	billingPolicyService   service.BillingPolicyService
	entitlementService     service.EntitlementService
	featureService         service.FeatureService
	pausePolicyService     service.PausePolicyService
	planCloneService       service.PlanCloneService
	planItemService        service.PlanItemService
	planService            service.PlanService
	planValidationService  service.PlanValidationService
	planVersionService     service.PlanVersionService
	prorationPolicyService service.ProrationPolicyService
	renewalEngineService   *service.RenewalEngineService
	renewalPolicyService   service.RenewalPolicyService
	subItemService         service.SubscriptionItemService
	subLifecycleService    service.SubscriptionLifecycleService
	subProvisioningService service.SubscriptionProvisioningService
	subService             service.SubscriptionService
	subValidationService   service.SubscriptionValidationService
	trialService           service.TrialService

	// handlers
	addonHandler           *handler.AddonHandler
	analyticsHandler       *handler.AnalyticsHandler
	benefitHandler         *handler.BenefitHandler
	billingPolicyHandler   *handler.BillingPolicyHandler
	entitlementHandler     *handler.EntitlementHandler
	featureHandler         *handler.FeatureHandler
	pausePolicyHandler     *handler.PausePolicyHandler
	planHandler            *handler.PlanHandler
	prorationPolicyHandler *handler.ProrationPolicyHandler
	renewalPolicyHandler   *handler.RenewalPolicyHandler
	subscriptionHandler    *handler.SubscriptionHandler
	trialHandler           *handler.TrialHandler
}

// NewSubscriptionInfraFactory creates a new factory with shared infrastructure and external services.
func NewSubscriptionInfraFactory(
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
	pricingService salesService.PricingService,
	couponService salesService.CouponService,
	discountEngineService salesService.DiscountEngineService,
	taxIntegrationService salesService.TaxIntegrationService,
	invoiceService salesService.InvoiceService,
) *SubscriptionInfraFactory {
	return &SubscriptionInfraFactory{
		logger:                logger.Named("subscription_infra"),
		pgClient:              pgClient,
		outboxRepo:            outboxRepo,
		idempotencyStore:      idempotencyStore,
		auditService:          auditService,
		pricingService:        pricingService,
		couponService:         couponService,
		discountEngineService: discountEngineService,
		taxIntegrationService: taxIntegrationService,
		invoiceService:        invoiceService,
	}
}

// -----------------------------------------------------------------------------
// Repository getters (lazy)
// -----------------------------------------------------------------------------

func (f *SubscriptionInfraFactory) AddonRepo() repository.AddonRepository {
	if f.addonRepo == nil {
		f.addonRepo = repository.NewAddonRepository(f.logger)
	}
	return f.addonRepo
}

func (f *SubscriptionInfraFactory) AnalyticsRepo() repository.AnalyticsRepository {
	if f.analyticsRepo == nil {
		f.analyticsRepo = repository.NewAnalyticsRepository(f.logger)
	}
	return f.analyticsRepo
}

func (f *SubscriptionInfraFactory) BenefitRepo() repository.BenefitRepository {
	if f.benefitRepo == nil {
		f.benefitRepo = repository.NewBenefitRepository(f.logger)
	}
	return f.benefitRepo
}

func (f *SubscriptionInfraFactory) BillingPolicyRepo() repository.BillingPolicyRepository {
	if f.billingPolicyRepo == nil {
		f.billingPolicyRepo = repository.NewBillingPolicyRepository(f.logger)
	}
	return f.billingPolicyRepo
}

func (f *SubscriptionInfraFactory) EntitlementRepo() repository.EntitlementRepository {
	if f.entitlementRepo == nil {
		f.entitlementRepo = repository.NewEntitlementRepository(f.logger)
	}
	return f.entitlementRepo
}

func (f *SubscriptionInfraFactory) FeatureRepo() repository.FeatureRepository {
	if f.featureRepo == nil {
		f.featureRepo = repository.NewFeatureRepository(f.logger)
	}
	return f.featureRepo
}

func (f *SubscriptionInfraFactory) LookupRepo() repository.LookupRepository {
	if f.lookupRepo == nil {
		f.lookupRepo = repository.NewLookupRepository(f.logger)
	}
	return f.lookupRepo
}

func (f *SubscriptionInfraFactory) PausePolicyRepo() repository.PausePolicyRepository {
	if f.pausePolicyRepo == nil {
		f.pausePolicyRepo = repository.NewPausePolicyRepository(f.logger)
	}
	return f.pausePolicyRepo
}

func (f *SubscriptionInfraFactory) PlanItemRepo() repository.PlanItemRepository {
	if f.planItemRepo == nil {
		f.planItemRepo = repository.NewPlanItemRepository(f.logger)
	}
	return f.planItemRepo
}

func (f *SubscriptionInfraFactory) PlanRepo() repository.PlanRepository {
	if f.planRepo == nil {
		f.planRepo = repository.NewPlanRepository(f.logger)
	}
	return f.planRepo
}

func (f *SubscriptionInfraFactory) ProrationPolicyRepo() repository.ProrationPolicyRepository {
	if f.prorationPolicyRepo == nil {
		f.prorationPolicyRepo = repository.NewProrationPolicyRepository(f.logger)
	}
	return f.prorationPolicyRepo
}

func (f *SubscriptionInfraFactory) RenewalPolicyRepo() repository.RenewalPolicyRepository {
	if f.renewalPolicyRepo == nil {
		f.renewalPolicyRepo = repository.NewRenewalPolicyRepository(f.logger)
	}
	return f.renewalPolicyRepo
}

func (f *SubscriptionInfraFactory) SubscriptionItemRepo() repository.SubscriptionItemRepository {
	if f.subItemRepo == nil {
		f.subItemRepo = repository.NewSubscriptionItemRepository(f.logger)
	}
	return f.subItemRepo
}

func (f *SubscriptionInfraFactory) SubscriptionRepo() repository.SubscriptionRepository {
	if f.subRepo == nil {
		f.subRepo = repository.NewSubscriptionRepository(f.logger)
	}
	return f.subRepo
}

func (f *SubscriptionInfraFactory) TimelineRepo() repository.TimelineRepository {
	if f.timelineRepo == nil {
		f.timelineRepo = repository.NewTimelineRepository(f.logger)
	}
	return f.timelineRepo
}

func (f *SubscriptionInfraFactory) TrialRepo() repository.TrialRepository {
	if f.trialRepo == nil {
		f.trialRepo = repository.NewTrialRepository(f.logger)
	}
	return f.trialRepo
}

func (f *SubscriptionInfraFactory) UsageRepo() repository.UsageRepository {
	if f.usageRepo == nil {
		f.usageRepo = repository.NewUsageRepository(f.logger)
	}
	return f.usageRepo
}

func (f *SubscriptionInfraFactory) VersionRepo() repository.VersionRepository {
	if f.versionRepo == nil {
		f.versionRepo = repository.NewVersionRepository(f.logger)
	}
	return f.versionRepo
}

// -----------------------------------------------------------------------------
// Service getters (lazy)
// -----------------------------------------------------------------------------

func (f *SubscriptionInfraFactory) AddonService() service.AddonService {
	if f.addonService == nil {
		f.addonService = service.NewAddonService(
			f.AddonRepo(),
			f.BillingPolicyRepo(),
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.pgClient,
			f.logger,
		)
	}
	return f.addonService
}

func (f *SubscriptionInfraFactory) AnalyticsQueryService() service.AnalyticsQueryService {
	if f.analyticsQueryService == nil {
		f.analyticsQueryService = service.NewAnalyticsQueryService(
			f.AnalyticsRepo(),
			f.pgClient.DB,
			f.logger,
		)
	}
	return f.analyticsQueryService
}

func (f *SubscriptionInfraFactory) AnalyticsService() service.SubscriptionAnalyticsService {
	if f.analyticsService == nil {
		f.analyticsService = service.NewSubscriptionAnalyticsService(
			f.AnalyticsRepo(),
			f.SubscriptionRepo(),
			f.SubscriptionItemRepo(),
			f.PlanRepo(),
			f.PlanItemRepo(),
			f.BenefitRepo(),
			f.BillingPolicyRepo(),
			f.RenewalPolicyRepo(),
			f.PausePolicyRepo(),
			f.EntitlementRepo(),
			f.FeatureRepo(),
			f.idempotencyStore,
			f.pgClient,
			f.logger,
		)
	}
	return f.analyticsService
}

func (f *SubscriptionInfraFactory) BenefitService() service.BenefitService {
	if f.benefitService == nil {
		f.benefitService = service.NewBenefitService(
			f.BenefitRepo(),
			f.PlanItemRepo(),
			f.outboxRepo,
			f.idempotencyStore,
			f.pgClient,
			f.logger,
			f.auditService,
		)
	}
	return f.benefitService
}

func (f *SubscriptionInfraFactory) BillingEngineService() *service.BillingEngineService {
	if f.billingEngineService == nil {
		f.billingEngineService = service.NewBillingEngineService(
			f.SubscriptionRepo(),
			f.SubscriptionItemRepo(),
			f.PlanRepo(),
			f.PlanItemRepo(),
			f.BillingPolicyRepo(),
			f.ProrationPolicyRepo(),
			f.RenewalPolicyRepo(),
			f.pricingService,
			f.couponService,
			f.discountEngineService,
			f.taxIntegrationService,
			f.invoiceService,
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.billingEngineService
}

func (f *SubscriptionInfraFactory) BillingPolicyService() service.BillingPolicyService {
	if f.billingPolicyService == nil {
		f.billingPolicyService = service.NewBillingPolicyService(
			f.BillingPolicyRepo(),
			f.LookupRepo(),
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.pgClient,
			f.logger,
		)
	}
	return f.billingPolicyService
}

func (f *SubscriptionInfraFactory) EntitlementService() service.EntitlementService {
	if f.entitlementService == nil {
		f.entitlementService = service.NewEntitlementService(
			f.EntitlementRepo(),
			f.PlanItemRepo(),
			f.PlanRepo(),
			f.SubscriptionRepo(),
			f.SubscriptionItemRepo(),
			f.UsageRepo(),
			f.FeatureRepo(),
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.pgClient,
			f.logger,
		)
	}
	return f.entitlementService
}

func (f *SubscriptionInfraFactory) FeatureService() service.FeatureService {
	if f.featureService == nil {
		f.featureService = service.NewFeatureService(
			f.FeatureRepo(),
			f.auditService,
			f.outboxRepo,
			f.idempotencyStore,
			f.pgClient,
			f.logger,
		)
	}
	return f.featureService
}

func (f *SubscriptionInfraFactory) PausePolicyService() service.PausePolicyService {
	if f.pausePolicyService == nil {
		f.pausePolicyService = service.NewPausePolicyService(
			f.PausePolicyRepo(),
			f.PlanRepo(),
			f.idempotencyStore,
			f.outboxRepo,
			f.auditService,
			f.pgClient,
			f.logger,
		)
	}
	return f.pausePolicyService
}

func (f *SubscriptionInfraFactory) PlanCloneService() service.PlanCloneService {
	if f.planCloneService == nil {
		f.planCloneService = service.NewPlanCloneService(
			f.PlanRepo(),
			f.PlanItemRepo(),
			f.BenefitRepo(),
			f.EntitlementRepo(),
			f.BillingPolicyRepo(),
			f.RenewalPolicyRepo(),
			f.PausePolicyRepo(),
			f.ProrationPolicyRepo(),
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.pgClient,
			f.logger,
		)
	}
	return f.planCloneService
}

func (f *SubscriptionInfraFactory) PlanItemService() service.PlanItemService {
	if f.planItemService == nil {
		f.planItemService = service.NewPlanItemService(
			f.PlanItemRepo(),
			f.PlanRepo(),
			f.SubscriptionRepo(),
			f.SubscriptionItemRepo(),
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.pgClient,
			f.logger,
		)
	}
	return f.planItemService
}

func (f *SubscriptionInfraFactory) PlanService() service.PlanService {
	if f.planService == nil {
		f.planService = service.NewPlanService(
			f.PlanRepo(),
			f.PlanItemRepo(),
			f.SubscriptionRepo(),
			f.PlanValidationService(),
			f.auditService,
			f.outboxRepo,
			f.idempotencyStore,
			f.pgClient,
			f.logger,
		)
	}
	return f.planService
}

func (f *SubscriptionInfraFactory) PlanValidationService() service.PlanValidationService {
	if f.planValidationService == nil {
		f.planValidationService = service.NewPlanValidationService(
			f.PlanRepo(),
			f.BillingPolicyRepo(),
			f.RenewalPolicyRepo(),
			f.PausePolicyRepo(),
			f.ProrationPolicyRepo(),
			f.logger,
		)
	}
	return f.planValidationService
}

func (f *SubscriptionInfraFactory) PlanVersionService() service.PlanVersionService {
	if f.planVersionService == nil {
		f.planVersionService = service.NewPlanVersionService(
			f.PlanRepo(),
			f.VersionRepo(),
			f.PlanItemRepo(),
			f.BenefitRepo(),
			f.EntitlementRepo(),
			f.BillingPolicyRepo(),
			f.RenewalPolicyRepo(),
			f.PausePolicyRepo(),
			f.ProrationPolicyRepo(),
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.pgClient,
			f.logger,
		)
	}
	return f.planVersionService
}

func (f *SubscriptionInfraFactory) ProrationPolicyService() service.ProrationPolicyService {
	if f.prorationPolicyService == nil {
		f.prorationPolicyService = service.NewProrationPolicyService(
			f.ProrationPolicyRepo(),
			f.PlanRepo(),
			f.auditService,
			f.outboxRepo,
			f.idempotencyStore,
			f.pgClient,
			f.logger,
		)
	}
	return f.prorationPolicyService
}

func (f *SubscriptionInfraFactory) RenewalEngineService() *service.RenewalEngineService {
	if f.renewalEngineService == nil {
		f.renewalEngineService = service.NewRenewalEngineService(
			f.SubscriptionRepo(),
			f.PlanRepo(),
			f.RenewalPolicyRepo(),
			f.BillingEngineService(),
			f.SubscriptionLifecycleService(),
			f.logger,
		)
	}
	return f.renewalEngineService
}

func (f *SubscriptionInfraFactory) RenewalPolicyService() service.RenewalPolicyService {
	if f.renewalPolicyService == nil {
		f.renewalPolicyService = service.NewRenewalPolicyService(
			f.RenewalPolicyRepo(),
			f.pgClient,
			f.logger,
			f.auditService,
			f.outboxRepo,
			f.idempotencyStore,
		)
	}
	return f.renewalPolicyService
}

func (f *SubscriptionInfraFactory) SubscriptionItemService() service.SubscriptionItemService {
	if f.subItemService == nil {
		f.subItemService = service.NewSubscriptionItemService(
			f.SubscriptionItemRepo(),
			f.PlanItemRepo(),
			f.AddonRepo(),
			f.SubscriptionRepo(),
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.pgClient,
			f.logger,
		)
	}
	return f.subItemService
}

func (f *SubscriptionInfraFactory) SubscriptionLifecycleService() service.SubscriptionLifecycleService {
	if f.subLifecycleService == nil {
		f.subLifecycleService = service.NewSubscriptionLifecycleService(
			f.SubscriptionRepo(),
			f.SubscriptionItemRepo(),
			f.TimelineRepo(),
			f.TrialRepo(),
			f.UsageRepo(),
			f.PlanRepo(),
			f.PlanItemRepo(),
			f.EntitlementService(),
			f.SubscriptionValidationService(),
			f.BillingEngineService(),
			f.auditService,
			f.outboxRepo,
			f.idempotencyStore,
			f.pgClient,
			f.logger,
		)
	}
	return f.subLifecycleService
}

func (f *SubscriptionInfraFactory) SubscriptionProvisioningService() service.SubscriptionProvisioningService {
	if f.subProvisioningService == nil {
		f.subProvisioningService = service.NewSubscriptionProvisioningService(
			f.SubscriptionRepo(),
			f.SubscriptionItemRepo(),
			f.PlanRepo(),
			f.PlanItemRepo(),
			f.EntitlementRepo(),
			f.BenefitRepo(),
			f.UsageRepo(),
			f.TrialRepo(),
			f.TimelineRepo(),
			f.FeatureRepo(),
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.pgClient,
			f.logger,
		)
	}
	return f.subProvisioningService
}

// -----------------------------------------------------------------------------
// FIXED: SubscriptionService now includes PlanItemRepository
// -----------------------------------------------------------------------------
func (f *SubscriptionInfraFactory) SubscriptionService() service.SubscriptionService {
	if f.subService == nil {
		f.subService = service.NewSubscriptionService(
			f.SubscriptionRepo(),
			f.SubscriptionItemRepo(),
			f.TimelineRepo(),
			f.PlanRepo(),
			f.PlanItemRepo(), // <-- ADDED: PlanItemRepository
			f.SubscriptionValidationService(),
			f.auditService,
			f.outboxRepo,
			f.idempotencyStore,
			f.pgClient,
			f.logger,
		)
	}
	return f.subService
}

func (f *SubscriptionInfraFactory) SubscriptionValidationService() service.SubscriptionValidationService {
	if f.subValidationService == nil {
		f.subValidationService = service.NewSubscriptionValidationService(
			f.SubscriptionRepo(),
			f.SubscriptionItemRepo(),
			f.PlanRepo(),
			f.AddonRepo(),
			f.TrialRepo(),
			f.UsageRepo(),
			f.EntitlementRepo(),
			f.pgClient,
			f.logger,
		)
	}
	return f.subValidationService
}

func (f *SubscriptionInfraFactory) TrialService() service.TrialService {
	if f.trialService == nil {
		f.trialService = service.NewTrialService(
			f.TrialRepo(),
			f.SubscriptionRepo(),
			f.auditService,
			f.outboxRepo,
			f.idempotencyStore,
			f.pgClient,
			f.logger,
		)
	}
	return f.trialService
}

// -----------------------------------------------------------------------------
// Handler getters (lazy)
// -----------------------------------------------------------------------------

func (f *SubscriptionInfraFactory) AddonHandler() *handler.AddonHandler {
	if f.addonHandler == nil {
		f.addonHandler = handler.NewAddonHandler(f.AddonService(), f.logger)
	}
	return f.addonHandler
}

func (f *SubscriptionInfraFactory) AnalyticsHandler() *handler.AnalyticsHandler {
	if f.analyticsHandler == nil {
		f.analyticsHandler = handler.NewAnalyticsHandler(f.AnalyticsQueryService(), f.logger)
	}
	return f.analyticsHandler
}

func (f *SubscriptionInfraFactory) BenefitHandler() *handler.BenefitHandler {
	if f.benefitHandler == nil {
		f.benefitHandler = handler.NewBenefitHandler(f.BenefitService(), f.logger)
	}
	return f.benefitHandler
}

func (f *SubscriptionInfraFactory) BillingPolicyHandler() *handler.BillingPolicyHandler {
	if f.billingPolicyHandler == nil {
		f.billingPolicyHandler = handler.NewBillingPolicyHandler(f.BillingPolicyService(), f.logger)
	}
	return f.billingPolicyHandler
}

func (f *SubscriptionInfraFactory) EntitlementHandler() *handler.EntitlementHandler {
	if f.entitlementHandler == nil {
		f.entitlementHandler = handler.NewEntitlementHandler(f.EntitlementService(), f.logger)
	}
	return f.entitlementHandler
}

func (f *SubscriptionInfraFactory) FeatureHandler() *handler.FeatureHandler {
	if f.featureHandler == nil {
		f.featureHandler = handler.NewFeatureHandler(f.FeatureService(), f.logger)
	}
	return f.featureHandler
}

func (f *SubscriptionInfraFactory) PausePolicyHandler() *handler.PausePolicyHandler {
	if f.pausePolicyHandler == nil {
		f.pausePolicyHandler = handler.NewPausePolicyHandler(f.PausePolicyService(), f.logger)
	}
	return f.pausePolicyHandler
}

func (f *SubscriptionInfraFactory) PlanHandler() *handler.PlanHandler {
	if f.planHandler == nil {
		f.planHandler = handler.NewPlanHandler(
			f.PlanService(),
			f.PlanItemService(),
			f.PlanCloneService(),
			f.PlanVersionService(),
			f.logger,
		)
	}
	return f.planHandler
}

func (f *SubscriptionInfraFactory) ProrationPolicyHandler() *handler.ProrationPolicyHandler {
	if f.prorationPolicyHandler == nil {
		f.prorationPolicyHandler = handler.NewProrationPolicyHandler(f.ProrationPolicyService(), f.logger)
	}
	return f.prorationPolicyHandler
}

func (f *SubscriptionInfraFactory) RenewalPolicyHandler() *handler.RenewalPolicyHandler {
	if f.renewalPolicyHandler == nil {
		f.renewalPolicyHandler = handler.NewRenewalPolicyHandler(f.RenewalPolicyService(), f.logger)
	}
	return f.renewalPolicyHandler
}

// -----------------------------------------------------------------------------
// FIXED: SubscriptionHandler now includes BillingEngineService
// -----------------------------------------------------------------------------
func (f *SubscriptionInfraFactory) SubscriptionHandler() *handler.SubscriptionHandler {
	if f.subscriptionHandler == nil {
		f.subscriptionHandler = handler.NewSubscriptionHandler(
			f.SubscriptionService(),
			f.SubscriptionLifecycleService(),
			f.SubscriptionItemService(),
			f.SubscriptionProvisioningService(),
			f.BillingEngineService(), // <-- ADDED: BillingEngineService
			f.logger,
		)
	}
	return f.subscriptionHandler
}

func (f *SubscriptionInfraFactory) TrialHandler() *handler.TrialHandler {
	if f.trialHandler == nil {
		f.trialHandler = handler.NewTrialHandler(f.TrialService(), f.logger)
	}
	return f.trialHandler
}

// -----------------------------------------------------------------------------
// Route registration
// -----------------------------------------------------------------------------

// RegisterRoutes mounts all subscription routes using the pre‑defined router.
func (f *SubscriptionInfraFactory) RegisterRoutes(r chi.Router) {
	handlers := &router.SubscriptionHandlers{
		AddonHandler:           f.AddonHandler(),
		AnalyticsHandler:       f.AnalyticsHandler(),
		BenefitHandler:         f.BenefitHandler(),
		BillingPolicyHandler:   f.BillingPolicyHandler(),
		EntitlementHandler:     f.EntitlementHandler(),
		FeatureHandler:         f.FeatureHandler(),
		PausePolicyHandler:     f.PausePolicyHandler(),
		PlanHandler:            f.PlanHandler(),
		ProrationPolicyHandler: f.ProrationPolicyHandler(),
		RenewalPolicyHandler:   f.RenewalPolicyHandler(),
		SubscriptionHandler:    f.SubscriptionHandler(),
		TrialHandler:           f.TrialHandler(),
	}
	router.RegisterSubscriptionRoutes(r, handlers, f.logger)
}

// SubscriptionHandlers returns all subscription handlers for route registration.
func (f *SubscriptionInfraFactory) SubscriptionHandlers() *router.SubscriptionHandlers {
	return &router.SubscriptionHandlers{
		AddonHandler:           f.AddonHandler(),
		AnalyticsHandler:       f.AnalyticsHandler(),
		BenefitHandler:         f.BenefitHandler(),
		BillingPolicyHandler:   f.BillingPolicyHandler(),
		EntitlementHandler:     f.EntitlementHandler(),
		FeatureHandler:         f.FeatureHandler(),
		PausePolicyHandler:     f.PausePolicyHandler(),
		PlanHandler:            f.PlanHandler(),
		ProrationPolicyHandler: f.ProrationPolicyHandler(),
		RenewalPolicyHandler:   f.RenewalPolicyHandler(),
		SubscriptionHandler:    f.SubscriptionHandler(),
		TrialHandler:           f.TrialHandler(),
	}
}

func (f *SubscriptionInfraFactory) Close() {}

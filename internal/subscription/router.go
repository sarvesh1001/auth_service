package subscription

import (
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"auth-service/internal/middleware"
	"auth-service/internal/subscription/handler"
)

// SubscriptionHandlers groups all subscription sub‑module handlers.
type SubscriptionHandlers struct {
	AddonHandler           *handler.AddonHandler
	AnalyticsHandler       *handler.AnalyticsHandler
	BenefitHandler         *handler.BenefitHandler
	BillingPolicyHandler   *handler.BillingPolicyHandler
	EntitlementHandler     *handler.EntitlementHandler
	FeatureHandler         *handler.FeatureHandler
	PausePolicyHandler     *handler.PausePolicyHandler
	PlanHandler            *handler.PlanHandler
	ProrationPolicyHandler *handler.ProrationPolicyHandler
	RenewalPolicyHandler   *handler.RenewalPolicyHandler
	SubscriptionHandler    *handler.SubscriptionHandler
	TrialHandler           *handler.TrialHandler
}

// RegisterSubscriptionRoutes registers all subscription HTTP endpoints under /subscription.
func RegisterSubscriptionRoutes(
	r chi.Router,
	handlers *SubscriptionHandlers,
	logger *zap.Logger,
) {
	// ---------------------------------------------------------------------
	// Addon routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/addons", func(r chi.Router) {
		// Create
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
			Post("/", handlers.AddonHandler.CreateAddon)

		// Read (view)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.AddonHandler.ListAddons)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/search", handlers.AddonHandler.SearchAddons)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/active", handlers.AddonHandler.GetActiveAddons)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/name", handlers.AddonHandler.GetAddonByName)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/price-range", handlers.AddonHandler.GetAddonsByPriceRange)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/billing-policy/{billingPolicyId}", handlers.AddonHandler.GetAddonsByBillingPolicy)

		// Single addon operations
		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/", handlers.AddonHandler.GetAddon)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Head("/", handlers.AddonHandler.AddonExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/", handlers.AddonHandler.UpdateAddon)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
				Delete("/", handlers.AddonHandler.DeleteAddon)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/activate", handlers.AddonHandler.ActivateAddon)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/deactivate", handlers.AddonHandler.DeactivateAddon)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/restore", handlers.AddonHandler.RestoreAddon)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/price", handlers.AddonHandler.UpdateAddonPrice)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/billing-policy", handlers.AddonHandler.UpdateAddonBillingPolicy)
		})
	})

	// ---------------------------------------------------------------------
	// Analytics routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/analytics", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/dashboard", handlers.AnalyticsHandler.GetDashboard)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/subscriptions", handlers.AnalyticsHandler.GetSubscriptionMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/revenue", handlers.AnalyticsHandler.GetRevenueMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/mrr", handlers.AnalyticsHandler.GetMRR)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/arr", handlers.AnalyticsHandler.GetARR)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/churn", handlers.AnalyticsHandler.GetChurnMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/trials", handlers.AnalyticsHandler.GetTrialMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/top-plans", handlers.AnalyticsHandler.GetTopPlans)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/top-addons", handlers.AnalyticsHandler.GetTopAddons)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/top-customers", handlers.AnalyticsHandler.GetTopCustomers)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/usage", handlers.AnalyticsHandler.GetUsageMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/top-features", handlers.AnalyticsHandler.GetTopFeatures)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/renewals", handlers.AnalyticsHandler.GetRenewalMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/upcoming-renewals", handlers.AnalyticsHandler.GetUpcomingRenewals)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/plan-change-metrics", handlers.AnalyticsHandler.GetPlanChangeMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/plan-change-trend", handlers.AnalyticsHandler.GetPlanChangeTrend)
	})

	// ---------------------------------------------------------------------
	// Benefit routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/benefits", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
			Post("/", handlers.BenefitHandler.CreateBenefit)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.BenefitHandler.ListBenefits)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/search", handlers.BenefitHandler.SearchBenefits)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/by-plan-item/{planItemId}", handlers.BenefitHandler.GetBenefitsByPlanItem)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/by-type", handlers.BenefitHandler.GetBenefitsByType)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/exists-by-type", handlers.BenefitHandler.ExistsByType)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
			Put("/replace/{planItemId}", handlers.BenefitHandler.ReplaceBenefitsByPlanItem)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
			Delete("/by-plan-item/{planItemId}", handlers.BenefitHandler.DeleteBenefitsByPlanItem)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
			Post("/copy", handlers.BenefitHandler.CopyBenefitsToPlanItem)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/", handlers.BenefitHandler.GetBenefit)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/exists", handlers.BenefitHandler.BenefitExists)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/", handlers.BenefitHandler.UpdateBenefit)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
				Delete("/", handlers.BenefitHandler.DeleteBenefit)
		})
	})

	// ---------------------------------------------------------------------
	// Billing Policy routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/billing-policies", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
			Post("/", handlers.BillingPolicyHandler.CreateBillingPolicy)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.BillingPolicyHandler.ListBillingPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/search", handlers.BillingPolicyHandler.SearchBillingPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/active", handlers.BillingPolicyHandler.GetActiveBillingPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/name", handlers.BillingPolicyHandler.GetBillingPolicyByName)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/", handlers.BillingPolicyHandler.GetBillingPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Head("/", handlers.BillingPolicyHandler.BillingPolicyExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/", handlers.BillingPolicyHandler.UpdateBillingPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
				Delete("/", handlers.BillingPolicyHandler.DeleteBillingPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/activate", handlers.BillingPolicyHandler.ActivateBillingPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/deactivate", handlers.BillingPolicyHandler.DeactivateBillingPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/restore", handlers.BillingPolicyHandler.RestoreBillingPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/frequency", handlers.BillingPolicyHandler.UpdateBillingPolicyFrequency)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/model", handlers.BillingPolicyHandler.UpdateBillingPolicyModel)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/interval", handlers.BillingPolicyHandler.UpdateBillingPolicyInterval)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/advance-days", handlers.BillingPolicyHandler.UpdateBillingPolicyAdvanceDays)
		})
	})

	// ---------------------------------------------------------------------
	// Entitlement routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/entitlements", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
			Post("/", handlers.EntitlementHandler.CreateEntitlement)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.EntitlementHandler.ListEntitlements)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/search", handlers.EntitlementHandler.SearchEntitlements)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
			Post("/grant", handlers.EntitlementHandler.GrantEntitlementsToSubscription)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
			Post("/revoke", handlers.EntitlementHandler.RevokeEntitlementsFromSubscription)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
			Post("/refresh", handlers.EntitlementHandler.RefreshSubscriptionEntitlements)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/", handlers.EntitlementHandler.GetEntitlement)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/", handlers.EntitlementHandler.UpdateEntitlement)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
				Delete("/", handlers.EntitlementHandler.DeleteEntitlement)
		})
	})

	r.Route("/subscription/plan-items/{planItemId}/entitlements", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.EntitlementHandler.GetEntitlementsByPlanItem)
	})

	r.Route("/subscription/subscriptions/{subscriptionId}/entitlements", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.EntitlementHandler.GetEntitlementsBySubscription)
	})

	// ---------------------------------------------------------------------
	// Feature routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/features", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
			Post("/", handlers.FeatureHandler.CreateFeature)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.FeatureHandler.ListFeatures)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/search", handlers.FeatureHandler.SearchFeatures)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/active", handlers.FeatureHandler.GetActiveFeatures)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/by-module", handlers.FeatureHandler.GetFeaturesByModule)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/by-feature-group", handlers.FeatureHandler.GetFeaturesByFeatureGroup)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/by-permission-scope", handlers.FeatureHandler.GetFeaturesByPermissionScope)

		// Operations using query parameter "feature_key"
		r.Route("/", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/get", handlers.FeatureHandler.GetFeature)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Head("/exists", handlers.FeatureHandler.FeatureExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/update", handlers.FeatureHandler.UpdateFeature)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
				Delete("/delete", handlers.FeatureHandler.DeleteFeature)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/activate", handlers.FeatureHandler.ActivateFeature)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/deactivate", handlers.FeatureHandler.DeactivateFeature)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/update-module", handlers.FeatureHandler.UpdateFeatureModule)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/update-feature-group", handlers.FeatureHandler.UpdateFeatureFeatureGroup)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/update-permission-scope", handlers.FeatureHandler.UpdateFeaturePermissionScope)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/update-description", handlers.FeatureHandler.UpdateFeatureDescription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/update-default-limit", handlers.FeatureHandler.UpdateFeatureDefaultLimit)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/update-depends-on", handlers.FeatureHandler.UpdateFeatureDependsOn)
		})
	})

	// ---------------------------------------------------------------------
	// Pause Policy routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/pause-policies", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
			Post("/", handlers.PausePolicyHandler.CreatePausePolicy)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.PausePolicyHandler.ListPausePolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/search", handlers.PausePolicyHandler.SearchPausePolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/active", handlers.PausePolicyHandler.GetActivePausePolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/name", handlers.PausePolicyHandler.GetPausePolicyByName)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/by-max-days", handlers.PausePolicyHandler.GetPausePoliciesByMaxDays)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/by-allowed-reason", handlers.PausePolicyHandler.GetPausePoliciesByAllowedReason)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/", handlers.PausePolicyHandler.GetPausePolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Head("/", handlers.PausePolicyHandler.ExistsPausePolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/", handlers.PausePolicyHandler.UpdatePausePolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
				Delete("/", handlers.PausePolicyHandler.DeletePausePolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/activate", handlers.PausePolicyHandler.ActivatePausePolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/deactivate", handlers.PausePolicyHandler.DeactivatePausePolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/restore", handlers.PausePolicyHandler.RestorePausePolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/max-pause-days", handlers.PausePolicyHandler.UpdateMaxPauseDays)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/freeze-days", handlers.PausePolicyHandler.UpdateFreezeDays)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/allowed-reasons", handlers.PausePolicyHandler.AddAllowedReason)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Delete("/allowed-reasons", handlers.PausePolicyHandler.RemoveAllowedReason)
		})
	})

	// ---------------------------------------------------------------------
	// Plan routes (includes plans, items, versions)
	// ---------------------------------------------------------------------
	r.Route("/subscription/plans", func(r chi.Router) {
		// Plan CRUD
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
			Post("/", handlers.PlanHandler.CreatePlan)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.PlanHandler.ListPlans)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/search", handlers.PlanHandler.SearchPlans)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/active", handlers.PlanHandler.GetActivePlans)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/archived", handlers.PlanHandler.GetArchivedPlans)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/", handlers.PlanHandler.GetPlan)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/", handlers.PlanHandler.UpdatePlan)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
				Delete("/", handlers.PlanHandler.DeletePlan)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/activate", handlers.PlanHandler.ActivatePlan)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/deactivate", handlers.PlanHandler.DeactivatePlan)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/restore", handlers.PlanHandler.RestorePlan)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/price", handlers.PlanHandler.UpdatePlanPrice)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/duration", handlers.PlanHandler.UpdatePlanDuration)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/billing-policy", handlers.PlanHandler.UpdatePlanBillingPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/renewal-policy", handlers.PlanHandler.UpdatePlanRenewalPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/pause-policy", handlers.PlanHandler.UpdatePlanPausePolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/proration-policy", handlers.PlanHandler.UpdatePlanProrationPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
				Post("/clone", handlers.PlanHandler.ClonePlan)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/clone-preview", handlers.PlanHandler.PreviewClonePlan)
		})

		// Plan Items
		r.Route("/{planId}/items", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
				Post("/", handlers.PlanHandler.CreatePlanItem)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
				Post("/bulk", handlers.PlanHandler.BulkCreatePlanItems)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/", handlers.PlanHandler.ListPlanItems)

			r.Route("/{itemId}", func(r chi.Router) {
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
					Get("/", handlers.PlanHandler.GetPlanItem)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
					Put("/", handlers.PlanHandler.UpdatePlanItem)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
					Delete("/", handlers.PlanHandler.DeletePlanItem)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
					Patch("/activate", handlers.PlanHandler.ActivatePlanItem)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
					Patch("/deactivate", handlers.PlanHandler.DeactivatePlanItem)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
					Post("/restore", handlers.PlanHandler.RestorePlanItem)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
					Patch("/price", handlers.PlanHandler.UpdatePlanItemPrice)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
					Post("/move-to/{targetPlanId}", handlers.PlanHandler.MovePlanItem)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
					Post("/copy-to/{targetPlanId}", handlers.PlanHandler.CopyPlanItem)
			})
		})

		// Plan Versions
		r.Route("/{planId}/versions", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
				Post("/", handlers.PlanHandler.CreatePlanVersion)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/latest", handlers.PlanHandler.GetLatestPlanVersion)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/published", handlers.PlanHandler.GetPublishedPlanVersion)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
				Post("/clone", handlers.PlanHandler.ClonePlanVersion)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/rollback", handlers.PlanHandler.RollbackPlanVersion)

			r.Route("/{versionId}", func(r chi.Router) {
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
					Post("/publish", handlers.PlanHandler.PublishPlanVersion)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
					Post("/unpublish", handlers.PlanHandler.UnpublishPlanVersion)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
					Post("/archive", handlers.PlanHandler.ArchivePlanVersion)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
					Post("/restore", handlers.PlanHandler.RestorePlanVersion)
			})
		})

		// Version comparison across plans
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/versions/compare", handlers.PlanHandler.ComparePlanVersions)
	})

	// ---------------------------------------------------------------------
	// Proration Policy routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/proration-policies", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
			Post("/", handlers.ProrationPolicyHandler.CreateProrationPolicy)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.ProrationPolicyHandler.ListProrationPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/search", handlers.ProrationPolicyHandler.SearchProrationPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/active", handlers.ProrationPolicyHandler.GetActiveProrationPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/name", handlers.ProrationPolicyHandler.GetProrationPolicyByName)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/upgrade-type/{upgrade_type}", handlers.ProrationPolicyHandler.GetProrationPoliciesByUpgradeType)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/downgrade-type/{downgrade_type}", handlers.ProrationPolicyHandler.GetProrationPoliciesByDowngradeType)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/", handlers.ProrationPolicyHandler.GetProrationPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Head("/", handlers.ProrationPolicyHandler.ProrationPolicyExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/", handlers.ProrationPolicyHandler.UpdateProrationPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
				Delete("/", handlers.ProrationPolicyHandler.DeleteProrationPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/activate", handlers.ProrationPolicyHandler.ActivateProrationPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/deactivate", handlers.ProrationPolicyHandler.DeactivateProrationPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/restore", handlers.ProrationPolicyHandler.RestoreProrationPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/upgrade-type", handlers.ProrationPolicyHandler.UpdateProrationPolicyUpgradeType)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/downgrade-type", handlers.ProrationPolicyHandler.UpdateProrationPolicyDowngradeType)
		})
	})

	// ---------------------------------------------------------------------
	// Renewal Policy routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/renewal-policies", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
			Post("/", handlers.RenewalPolicyHandler.CreateRenewalPolicy)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.RenewalPolicyHandler.ListRenewalPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/search", handlers.RenewalPolicyHandler.SearchRenewalPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/active", handlers.RenewalPolicyHandler.GetActiveRenewalPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/auto-renew", handlers.RenewalPolicyHandler.GetAutoRenewPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/manual-renew", handlers.RenewalPolicyHandler.GetManualRenewPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/name", handlers.RenewalPolicyHandler.GetRenewalPolicyByName)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/", handlers.RenewalPolicyHandler.GetRenewalPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Head("/", handlers.RenewalPolicyHandler.RenewalPolicyExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/", handlers.RenewalPolicyHandler.UpdateRenewalPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
				Delete("/", handlers.RenewalPolicyHandler.DeleteRenewalPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/activate", handlers.RenewalPolicyHandler.ActivateRenewalPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/deactivate", handlers.RenewalPolicyHandler.DeactivateRenewalPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/restore", handlers.RenewalPolicyHandler.RestoreRenewalPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/auto-renew", handlers.RenewalPolicyHandler.UpdateAutoRenew)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/grace-period", handlers.RenewalPolicyHandler.UpdateGracePeriod)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/late-fee", handlers.RenewalPolicyHandler.UpdateLateFee)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Patch("/notice-period", handlers.RenewalPolicyHandler.UpdateNoticePeriod)
		})
	})

	// ---------------------------------------------------------------------
	// Subscription routes (core)
	// ---------------------------------------------------------------------
	r.Route("/subscription", func(r chi.Router) {
		// Core CRUD
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
			Post("/", handlers.SubscriptionHandler.CreateSubscription)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.SubscriptionHandler.ListSubscriptions)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/search", handlers.SubscriptionHandler.SearchSubscriptions)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/customer/{customerId}", handlers.SubscriptionHandler.GetByCustomer)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/plan/{planId}", handlers.SubscriptionHandler.GetByPlan)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/expiring", handlers.SubscriptionHandler.GetExpiring)

		// Single subscription
		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/", handlers.SubscriptionHandler.GetSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/", handlers.SubscriptionHandler.UpdateSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
				Delete("/", handlers.SubscriptionHandler.DeleteSubscription)

			// Lifecycle
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/activate", handlers.SubscriptionHandler.ActivateSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/reactivate", handlers.SubscriptionHandler.ReactivateSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/suspend", handlers.SubscriptionHandler.SuspendSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/pause", handlers.SubscriptionHandler.PauseSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/resume", handlers.SubscriptionHandler.ResumeSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/renew", handlers.SubscriptionHandler.RenewSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/expire", handlers.SubscriptionHandler.ExpireSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/upgrade", handlers.SubscriptionHandler.UpgradeSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/downgrade", handlers.SubscriptionHandler.DowngradeSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/change-plan", handlers.SubscriptionHandler.ChangePlan)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/cancel", handlers.SubscriptionHandler.CancelSubscription)

			// Items
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/items", handlers.SubscriptionHandler.GetSubscriptionItems)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
				Post("/items", handlers.SubscriptionHandler.AddSubscriptionItem)

			// Provisioning
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/provision", handlers.SubscriptionHandler.ProvisionSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/deprovision", handlers.SubscriptionHandler.DeprovisionSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/reprovision", handlers.SubscriptionHandler.ReprovisionSubscription)
		})

		// Standalone items
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
			Put("/items/{itemId}", handlers.SubscriptionHandler.UpdateSubscriptionItem)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
			Delete("/items/{itemId}", handlers.SubscriptionHandler.DeleteSubscriptionItem)
	})

	// ---------------------------------------------------------------------
	// Trial routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/trials", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create", logger)).
			Post("/", handlers.TrialHandler.CreateTrial)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/", handlers.TrialHandler.ListTrials)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/search", handlers.TrialHandler.SearchTrials)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/active", handlers.TrialHandler.GetActiveTrials)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/expired", handlers.TrialHandler.GetExpiredTrials)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/converted", handlers.TrialHandler.GetConvertedTrials)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/expiring", handlers.TrialHandler.GetExpiringTrials)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/eligibility", handlers.TrialHandler.CheckEligibility)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
			Get("/by-subscription", handlers.TrialHandler.GetTrialBySubscription)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Get("/", handlers.TrialHandler.GetTrial)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view", logger)).
				Head("/", handlers.TrialHandler.TrialExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/", handlers.TrialHandler.UpdateTrial)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete", logger)).
				Delete("/", handlers.TrialHandler.DeleteTrial)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/start", handlers.TrialHandler.StartTrial)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/end", handlers.TrialHandler.EndTrial)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/extend", handlers.TrialHandler.ExtendTrial)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/convert", handlers.TrialHandler.ConvertTrial)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Post("/cancel", handlers.TrialHandler.CancelTrial)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/days", handlers.TrialHandler.UpdateTrialDays)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/start-date", handlers.TrialHandler.UpdateStartDate)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/end-date", handlers.TrialHandler.UpdateEndDate)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/usage", handlers.TrialHandler.UpdateUsage)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update", logger)).
				Put("/features", handlers.TrialHandler.UpdateFeatures)
		})
	})
}

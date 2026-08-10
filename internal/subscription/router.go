package subscription

import (
	"github.com/go-chi/chi/v5"

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
) {
	// ---------------------------------------------------------------------
	// Addon routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/addons", func(r chi.Router) {
		// Create
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.AddonHandler.CreateAddon)

		// Read (view)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.AddonHandler.ListAddons)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.AddonHandler.SearchAddons)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/active", handlers.AddonHandler.GetActiveAddons)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/name", handlers.AddonHandler.GetAddonByName)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/price-range", handlers.AddonHandler.GetAddonsByPriceRange)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/billing-policy/{billingPolicyId}", handlers.AddonHandler.GetAddonsByBillingPolicy)

		// Single addon operations
		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.AddonHandler.GetAddon)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Head("/", handlers.AddonHandler.AddonExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.AddonHandler.UpdateAddon)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.AddonHandler.DeleteAddon)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/activate", handlers.AddonHandler.ActivateAddon)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/deactivate", handlers.AddonHandler.DeactivateAddon)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/restore", handlers.AddonHandler.RestoreAddon)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/price", handlers.AddonHandler.UpdateAddonPrice)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/billing-policy", handlers.AddonHandler.UpdateAddonBillingPolicy)
		})
	})

	// ---------------------------------------------------------------------
	// Analytics routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/analytics", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/dashboard", handlers.AnalyticsHandler.GetDashboard)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/subscriptions", handlers.AnalyticsHandler.GetSubscriptionMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/revenue", handlers.AnalyticsHandler.GetRevenueMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/mrr", handlers.AnalyticsHandler.GetMRR)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/arr", handlers.AnalyticsHandler.GetARR)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/churn", handlers.AnalyticsHandler.GetChurnMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/trials", handlers.AnalyticsHandler.GetTrialMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/top-plans", handlers.AnalyticsHandler.GetTopPlans)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/top-addons", handlers.AnalyticsHandler.GetTopAddons)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/top-customers", handlers.AnalyticsHandler.GetTopCustomers)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/usage", handlers.AnalyticsHandler.GetUsageMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/top-features", handlers.AnalyticsHandler.GetTopFeatures)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/renewals", handlers.AnalyticsHandler.GetRenewalMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/upcoming-renewals", handlers.AnalyticsHandler.GetUpcomingRenewals)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/plan-change-metrics", handlers.AnalyticsHandler.GetPlanChangeMetrics)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/plan-change-trend", handlers.AnalyticsHandler.GetPlanChangeTrend)
	})

	// ---------------------------------------------------------------------
	// Benefit routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/benefits", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.BenefitHandler.CreateBenefit)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.BenefitHandler.ListBenefits)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.BenefitHandler.SearchBenefits)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-plan-item/{planItemId}", handlers.BenefitHandler.GetBenefitsByPlanItem)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-type", handlers.BenefitHandler.GetBenefitsByType)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/exists-by-type", handlers.BenefitHandler.ExistsByType)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Put("/replace/{planItemId}", handlers.BenefitHandler.ReplaceBenefitsByPlanItem)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
			Delete("/by-plan-item/{planItemId}", handlers.BenefitHandler.DeleteBenefitsByPlanItem)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/copy", handlers.BenefitHandler.CopyBenefitsToPlanItem)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.BenefitHandler.GetBenefit)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/exists", handlers.BenefitHandler.BenefitExists)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.BenefitHandler.UpdateBenefit)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.BenefitHandler.DeleteBenefit)
		})
	})

	// ---------------------------------------------------------------------
	// Billing Policy routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/billing-policies", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.BillingPolicyHandler.CreateBillingPolicy)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.BillingPolicyHandler.ListBillingPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.BillingPolicyHandler.SearchBillingPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/active", handlers.BillingPolicyHandler.GetActiveBillingPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/name", handlers.BillingPolicyHandler.GetBillingPolicyByName)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.BillingPolicyHandler.GetBillingPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Head("/", handlers.BillingPolicyHandler.BillingPolicyExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.BillingPolicyHandler.UpdateBillingPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.BillingPolicyHandler.DeleteBillingPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/activate", handlers.BillingPolicyHandler.ActivateBillingPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/deactivate", handlers.BillingPolicyHandler.DeactivateBillingPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/restore", handlers.BillingPolicyHandler.RestoreBillingPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/frequency", handlers.BillingPolicyHandler.UpdateBillingPolicyFrequency)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/model", handlers.BillingPolicyHandler.UpdateBillingPolicyModel)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/interval", handlers.BillingPolicyHandler.UpdateBillingPolicyInterval)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/advance-days", handlers.BillingPolicyHandler.UpdateBillingPolicyAdvanceDays)
		})
	})

	// ---------------------------------------------------------------------
	// Entitlement routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/entitlements", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.EntitlementHandler.CreateEntitlement)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.EntitlementHandler.ListEntitlements)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.EntitlementHandler.SearchEntitlements)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/grant", handlers.EntitlementHandler.GrantEntitlementsToSubscription)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/revoke", handlers.EntitlementHandler.RevokeEntitlementsFromSubscription)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/refresh", handlers.EntitlementHandler.RefreshSubscriptionEntitlements)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.EntitlementHandler.GetEntitlement)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.EntitlementHandler.UpdateEntitlement)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.EntitlementHandler.DeleteEntitlement)
		})
	})

	r.Route("/subscription/plan-items/{planItemId}/entitlements", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.EntitlementHandler.GetEntitlementsByPlanItem)
	})

	r.Route("/subscription/subscriptions/{subscriptionId}/entitlements", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.EntitlementHandler.GetEntitlementsBySubscription)
	})

	// ---------------------------------------------------------------------
	// Feature routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/features", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.FeatureHandler.CreateFeature)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.FeatureHandler.ListFeatures)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.FeatureHandler.SearchFeatures)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/active", handlers.FeatureHandler.GetActiveFeatures)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-module", handlers.FeatureHandler.GetFeaturesByModule)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-feature-group", handlers.FeatureHandler.GetFeaturesByFeatureGroup)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-permission-scope", handlers.FeatureHandler.GetFeaturesByPermissionScope)

		// Operations using query parameter "feature_key"
		r.Route("/", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/get", handlers.FeatureHandler.GetFeature)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Head("/exists", handlers.FeatureHandler.FeatureExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/update", handlers.FeatureHandler.UpdateFeature)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/delete", handlers.FeatureHandler.DeleteFeature)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/activate", handlers.FeatureHandler.ActivateFeature)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/deactivate", handlers.FeatureHandler.DeactivateFeature)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/update-module", handlers.FeatureHandler.UpdateFeatureModule)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/update-feature-group", handlers.FeatureHandler.UpdateFeatureFeatureGroup)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/update-permission-scope", handlers.FeatureHandler.UpdateFeaturePermissionScope)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/update-description", handlers.FeatureHandler.UpdateFeatureDescription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/update-default-limit", handlers.FeatureHandler.UpdateFeatureDefaultLimit)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/update-depends-on", handlers.FeatureHandler.UpdateFeatureDependsOn)
		})
	})

	// ---------------------------------------------------------------------
	// Pause Policy routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/pause-policies", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.PausePolicyHandler.CreatePausePolicy)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.PausePolicyHandler.ListPausePolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.PausePolicyHandler.SearchPausePolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/active", handlers.PausePolicyHandler.GetActivePausePolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/name", handlers.PausePolicyHandler.GetPausePolicyByName)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-max-days", handlers.PausePolicyHandler.GetPausePoliciesByMaxDays)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-allowed-reason", handlers.PausePolicyHandler.GetPausePoliciesByAllowedReason)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.PausePolicyHandler.GetPausePolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Head("/", handlers.PausePolicyHandler.ExistsPausePolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.PausePolicyHandler.UpdatePausePolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.PausePolicyHandler.DeletePausePolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/activate", handlers.PausePolicyHandler.ActivatePausePolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/deactivate", handlers.PausePolicyHandler.DeactivatePausePolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/restore", handlers.PausePolicyHandler.RestorePausePolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/max-pause-days", handlers.PausePolicyHandler.UpdateMaxPauseDays)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/freeze-days", handlers.PausePolicyHandler.UpdateFreezeDays)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/allowed-reasons", handlers.PausePolicyHandler.AddAllowedReason)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Delete("/allowed-reasons", handlers.PausePolicyHandler.RemoveAllowedReason)
		})
	})

	// ---------------------------------------------------------------------
	// Plan routes (includes plans, items, versions)
	// ---------------------------------------------------------------------
	r.Route("/subscription/plans", func(r chi.Router) {
		// Plan CRUD
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.PlanHandler.CreatePlan)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.PlanHandler.ListPlans)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.PlanHandler.SearchPlans)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/active", handlers.PlanHandler.GetActivePlans)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/archived", handlers.PlanHandler.GetArchivedPlans)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.PlanHandler.GetPlan)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.PlanHandler.UpdatePlan)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.PlanHandler.DeletePlan)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/activate", handlers.PlanHandler.ActivatePlan)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/deactivate", handlers.PlanHandler.DeactivatePlan)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/restore", handlers.PlanHandler.RestorePlan)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/price", handlers.PlanHandler.UpdatePlanPrice)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/duration", handlers.PlanHandler.UpdatePlanDuration)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/billing-policy", handlers.PlanHandler.UpdatePlanBillingPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/renewal-policy", handlers.PlanHandler.UpdatePlanRenewalPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/pause-policy", handlers.PlanHandler.UpdatePlanPausePolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/proration-policy", handlers.PlanHandler.UpdatePlanProrationPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Post("/clone", handlers.PlanHandler.ClonePlan)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/clone-preview", handlers.PlanHandler.PreviewClonePlan)
		})

		// Plan Items
		r.Route("/{planId}/items", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Post("/", handlers.PlanHandler.CreatePlanItem)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Post("/bulk", handlers.PlanHandler.BulkCreatePlanItems)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.PlanHandler.ListPlanItems)

			r.Route("/{itemId}", func(r chi.Router) {
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
					Get("/", handlers.PlanHandler.GetPlanItem)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Put("/", handlers.PlanHandler.UpdatePlanItem)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
					Delete("/", handlers.PlanHandler.DeletePlanItem)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Patch("/activate", handlers.PlanHandler.ActivatePlanItem)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Patch("/deactivate", handlers.PlanHandler.DeactivatePlanItem)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/restore", handlers.PlanHandler.RestorePlanItem)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Patch("/price", handlers.PlanHandler.UpdatePlanItemPrice)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/move-to/{targetPlanId}", handlers.PlanHandler.MovePlanItem)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
					Post("/copy-to/{targetPlanId}", handlers.PlanHandler.CopyPlanItem)
			})
		})

		// Plan Versions
		r.Route("/{planId}/versions", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Post("/", handlers.PlanHandler.CreatePlanVersion)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/latest", handlers.PlanHandler.GetLatestPlanVersion)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/published", handlers.PlanHandler.GetPublishedPlanVersion)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Post("/clone", handlers.PlanHandler.ClonePlanVersion)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/rollback", handlers.PlanHandler.RollbackPlanVersion)

			r.Route("/{versionId}", func(r chi.Router) {
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/publish", handlers.PlanHandler.PublishPlanVersion)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/unpublish", handlers.PlanHandler.UnpublishPlanVersion)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
					Post("/archive", handlers.PlanHandler.ArchivePlanVersion)
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/restore", handlers.PlanHandler.RestorePlanVersion)
			})
		})

		// Version comparison across plans
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/versions/compare", handlers.PlanHandler.ComparePlanVersions)
	})

	// ---------------------------------------------------------------------
	// Proration Policy routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/proration-policies", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.ProrationPolicyHandler.CreateProrationPolicy)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.ProrationPolicyHandler.ListProrationPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.ProrationPolicyHandler.SearchProrationPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/active", handlers.ProrationPolicyHandler.GetActiveProrationPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/name", handlers.ProrationPolicyHandler.GetProrationPolicyByName)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/upgrade-type/{upgrade_type}", handlers.ProrationPolicyHandler.GetProrationPoliciesByUpgradeType)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/downgrade-type/{downgrade_type}", handlers.ProrationPolicyHandler.GetProrationPoliciesByDowngradeType)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.ProrationPolicyHandler.GetProrationPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Head("/", handlers.ProrationPolicyHandler.ProrationPolicyExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.ProrationPolicyHandler.UpdateProrationPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.ProrationPolicyHandler.DeleteProrationPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/activate", handlers.ProrationPolicyHandler.ActivateProrationPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/deactivate", handlers.ProrationPolicyHandler.DeactivateProrationPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/restore", handlers.ProrationPolicyHandler.RestoreProrationPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/upgrade-type", handlers.ProrationPolicyHandler.UpdateProrationPolicyUpgradeType)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/downgrade-type", handlers.ProrationPolicyHandler.UpdateProrationPolicyDowngradeType)
		})
	})

	// ---------------------------------------------------------------------
	// Renewal Policy routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/renewal-policies", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.RenewalPolicyHandler.CreateRenewalPolicy)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.RenewalPolicyHandler.ListRenewalPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.RenewalPolicyHandler.SearchRenewalPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/active", handlers.RenewalPolicyHandler.GetActiveRenewalPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/auto-renew", handlers.RenewalPolicyHandler.GetAutoRenewPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/manual-renew", handlers.RenewalPolicyHandler.GetManualRenewPolicies)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/name", handlers.RenewalPolicyHandler.GetRenewalPolicyByName)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.RenewalPolicyHandler.GetRenewalPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Head("/", handlers.RenewalPolicyHandler.RenewalPolicyExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.RenewalPolicyHandler.UpdateRenewalPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.RenewalPolicyHandler.DeleteRenewalPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/activate", handlers.RenewalPolicyHandler.ActivateRenewalPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/deactivate", handlers.RenewalPolicyHandler.DeactivateRenewalPolicy)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/restore", handlers.RenewalPolicyHandler.RestoreRenewalPolicy)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/auto-renew", handlers.RenewalPolicyHandler.UpdateAutoRenew)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/grace-period", handlers.RenewalPolicyHandler.UpdateGracePeriod)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/late-fee", handlers.RenewalPolicyHandler.UpdateLateFee)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/notice-period", handlers.RenewalPolicyHandler.UpdateNoticePeriod)
		})
	})

	// ---------------------------------------------------------------------
	// Subscription routes (core)
	// ---------------------------------------------------------------------
	r.Route("/subscription", func(r chi.Router) {
		// Core CRUD
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.SubscriptionHandler.CreateSubscription)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.SubscriptionHandler.ListSubscriptions)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.SubscriptionHandler.SearchSubscriptions)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customer/{customerId}", handlers.SubscriptionHandler.GetByCustomer)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/plan/{planId}", handlers.SubscriptionHandler.GetByPlan)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/expiring", handlers.SubscriptionHandler.GetExpiring)

		// Single subscription
		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.SubscriptionHandler.GetSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.SubscriptionHandler.UpdateSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.SubscriptionHandler.DeleteSubscription)

			// Lifecycle
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/activate", handlers.SubscriptionHandler.ActivateSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/reactivate", handlers.SubscriptionHandler.ReactivateSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/suspend", handlers.SubscriptionHandler.SuspendSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/pause", handlers.SubscriptionHandler.PauseSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/resume", handlers.SubscriptionHandler.ResumeSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/renew", handlers.SubscriptionHandler.RenewSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/expire", handlers.SubscriptionHandler.ExpireSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/upgrade", handlers.SubscriptionHandler.UpgradeSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/downgrade", handlers.SubscriptionHandler.DowngradeSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/change-plan", handlers.SubscriptionHandler.ChangePlan)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/cancel", handlers.SubscriptionHandler.CancelSubscription)

			// Items
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/items", handlers.SubscriptionHandler.GetSubscriptionItems)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Post("/items", handlers.SubscriptionHandler.AddSubscriptionItem)

			// Provisioning
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/provision", handlers.SubscriptionHandler.ProvisionSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/deprovision", handlers.SubscriptionHandler.DeprovisionSubscription)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/reprovision", handlers.SubscriptionHandler.ReprovisionSubscription)
		})

		// Standalone items
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Put("/items/{itemId}", handlers.SubscriptionHandler.UpdateSubscriptionItem)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
			Delete("/items/{itemId}", handlers.SubscriptionHandler.DeleteSubscriptionItem)
	})

	// ---------------------------------------------------------------------
	// Trial routes
	// ---------------------------------------------------------------------
	r.Route("/subscription/trials", func(r chi.Router) {
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.TrialHandler.CreateTrial)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.TrialHandler.ListTrials)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.TrialHandler.SearchTrials)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/active", handlers.TrialHandler.GetActiveTrials)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/expired", handlers.TrialHandler.GetExpiredTrials)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/converted", handlers.TrialHandler.GetConvertedTrials)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/expiring", handlers.TrialHandler.GetExpiringTrials)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/eligibility", handlers.TrialHandler.CheckEligibility)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-subscription", handlers.TrialHandler.GetTrialBySubscription)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.TrialHandler.GetTrial)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Head("/", handlers.TrialHandler.TrialExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.TrialHandler.UpdateTrial)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.TrialHandler.DeleteTrial)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/start", handlers.TrialHandler.StartTrial)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/end", handlers.TrialHandler.EndTrial)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/extend", handlers.TrialHandler.ExtendTrial)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/convert", handlers.TrialHandler.ConvertTrial)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/cancel", handlers.TrialHandler.CancelTrial)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/days", handlers.TrialHandler.UpdateTrialDays)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/start-date", handlers.TrialHandler.UpdateStartDate)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/end-date", handlers.TrialHandler.UpdateEndDate)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/usage", handlers.TrialHandler.UpdateUsage)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/features", handlers.TrialHandler.UpdateFeatures)
		})
	})
}

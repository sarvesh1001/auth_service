package middleware

import (
	"net/http"
	"strings"

	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"

	"github.com/google/uuid"
)

// SubscriptionEnforcementMiddleware blocks requests for companies whose
// subscription is not in good standing.
//
// Rules:
//   - Admin sessions bypass entirely.
//   - Auth / billing / webhook / health paths are always allowed.
//   - trial / active      → full access.
//   - past_due            → read (GET/HEAD/OPTIONS) allowed, write blocked (402).
//   - pending             → everything blocked (402 `subscription_required`)
//     except billing/auth paths. Company exists but
//     no subscription has been provisioned yet.
//   - expired / cancelled → everything blocked (402) except billing/auth paths.
//
// Uses CompanyService.IsCompanyAllowed which lazy-caches in Redis (10 min TTL).
// Cache is invalidated by the service on any write that changes subscription state.
func SubscriptionEnforcementMiddleware(
	companyService *service.CompanyService,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// ---------------------------------------------------------
			// 1. Admin bypass – check session_type and JWT claims
			// ---------------------------------------------------------
			if sessionType, _ := ctx.Value("session_type").(string); sessionType == "admin" {
				next.ServeHTTP(w, r)
				return
			}
			if claims, ok := ctx.Value("jwt_claims").(*models.JWTClaims); ok &&
				claims.SessionType == "admin" {
				next.ServeHTTP(w, r)
				return
			}

			// ---------------------------------------------------------
			// 2. Auth / billing / webhook / health paths are always allowed
			// ---------------------------------------------------------
			if isBillingOrAuthPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// ---------------------------------------------------------
			// 3. Extract company ID from context
			// ---------------------------------------------------------
			companyIDStr, _ := ctx.Value("company_id").(string)
			if companyIDStr == "" {
				// No company context → allow (e.g., user-only endpoints).
				next.ServeHTTP(w, r)
				return
			}

			companyID := mustParseUUID(companyIDStr)
			if companyID == uuid.Nil {
				util.JSONError(w, http.StatusBadRequest, "invalid company id")
				return
			}

			// ---------------------------------------------------------
			// 4. Check via lazy-cached service method
			// ---------------------------------------------------------
			allowed, status, err := companyService.IsCompanyAllowed(ctx, companyID)
			if err != nil {
				util.JSONError(w, http.StatusNotFound, "company not found")
				return
			}

			// ---------------------------------------------------------
			// 5. Determine read vs write
			// ---------------------------------------------------------
			isWrite := r.Method != http.MethodGet &&
				r.Method != http.MethodHead &&
				r.Method != http.MethodOptions

			// ---------------------------------------------------------
			// 6. Enforce: not allowed → 402 with a status-specific code
			//    so the client can route to the right screen.
			// ---------------------------------------------------------
			if !allowed {
				switch status {
				case models.SubscriptionStatusPending:
					// Company exists but has never had a subscription
					// provisioned (created with 0/0/0). Route the client
					// to "get started" / checkout.
					util.JSONErrorWithCode(w, http.StatusPaymentRequired,
						"subscription_required",
						"Please subscribe to activate your company. "+
							"Visit billing to get started.")

				case models.SubscriptionStatusCancelled:
					util.JSONErrorWithCode(w, http.StatusPaymentRequired,
						"subscription_cancelled",
						"Your subscription was cancelled. "+
							"Reactivate to regain access.")

				default: // expired (or any other terminal state)
					util.JSONErrorWithCode(w, http.StatusPaymentRequired,
						"subscription_expired",
						"Your subscription has expired. "+
							"Please renew to regain access.")
				}
				return
			}

			// ---------------------------------------------------------
			// 7. past_due → read-only (writes blocked)
			// ---------------------------------------------------------
			if status == models.SubscriptionStatusPastDue && isWrite {
				util.JSONErrorWithCode(w, http.StatusPaymentRequired,
					"subscription_past_due",
					"Your subscription is past due. "+
						"Please renew to continue making changes.")
				return
			}

			// ---------------------------------------------------------
			// 8. Informational warning header for degraded states.
			//    Frontends can show a persistent banner.
			// ---------------------------------------------------------
			switch status {
			case models.SubscriptionStatusPastDue:
				w.Header().Set("X-Subscription-Warning", "past_due")
			case models.SubscriptionStatusPending:
				w.Header().Set("X-Subscription-Warning", "pending")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isBillingOrAuthPath returns true if the path is related to auth, billing,
// or health. These paths are always allowed, regardless of subscription status.
//
// This is what allows users to renew their subscription even when it has
// expired, and (new) to subscribe for the first time when the company is
// still in `pending` state. Anything that leads to a payment (view plans,
// checkout, view invoice, list payments, upgrade, cancel-to-downgrade, etc.)
// must be reachable regardless of the current subscription state.
func isBillingOrAuthPath(path string) bool {
	// 1. Prefix allow-list – reserved system endpoints.
	allowedPrefixes := []string{
		"/api/v1/auth/",
		"/api/v1/otp/",
		"/api/v1/admin-auth/",
		"/api/v1/setup/",
		"/api/v1/health",
		"/health",
		"/api/v1/webhooks/",
		"/api/v1/plans",
		// Subscription module – covers /subscriptions/plans,
		// /subscriptions/upgrade, /subscriptions/current,
		// /subscriptions/checkout, /subscriptions/invoices, etc.
		"/api/v1/subscriptions/",
		"/api/v1/subscription/",
	}
	for _, p := range allowedPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}

	// 2. Company-scoped billing endpoints – match anywhere in the path.
	//    e.g. /api/v1/companies/{id}/payments, /api/v1/companies/{id}/invoices
	if strings.Contains(path, "/payments") ||
		strings.Contains(path, "/invoices") ||
		strings.Contains(path, "/billing") ||
		strings.Contains(path, "/checkout") {
		return true
	}

	return false
}

// mustParseUUID is a small helper – returns uuid.Nil on error.
func mustParseUUID(s string) uuid.UUID {
	id, _ := uuid.Parse(s)
	return id
}

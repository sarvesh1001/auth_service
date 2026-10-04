package middleware

import (
	"context"
	"net/http"
	"strings"

	"auth-service/internal/locationctx"
	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"

	"github.com/google/uuid"
)

// AllLocationsSentinel is the reserved value for X-Location-ID that requests
// the company-wide (consolidated) view instead of a single physical location.
// Only users with location_scope == "ALL" are permitted to send it, and only
// for read operations — with the explicit exceptions listed below.
const AllLocationsSentinel = "ALL"

// Deprecated: use locationctx.* directly.
//
// Retained as aliases so existing references keep compiling during the
// migration to locationctx. New code must import locationctx and use
// locationctx.CtxMode / CtxLocationID / CtxAccessLevel instead.
const (
	CtxLocationMode        = locationctx.CtxMode
	CtxValidatedLocationID = locationctx.CtxLocationID
	CtxLocationAccessLevel = locationctx.CtxAccessLevel
)

// readOnlyPOSTSuffixes lists URL path suffixes for POST endpoints that are
// semantically reads — they use POST only because they accept a request body
// (e.g. batch-fetch by ID list). These are exempt from the "ALL location
// scope is read-only" guard, because there is no state mutation.
//
// Match against the path suffix so the rule works regardless of the
// /api/v1/companies/{companyID} prefix in front of the route.
var readOnlyPOSTSuffixes = []string{
	"/hr/employees/details",
	"/hr/employees",        // 👈 ADD THIS

	// add more here as batch-read endpoints are introduced
}

// allScopeWritePOSTSuffixes lists URL path suffixes for POST endpoints that
// are permitted to run under the company-wide ("ALL") scope even though they
// mutate state.
//
// These endpoints perform their OWN per-target location validation in the
// service layer, so the middleware does not need to block them. The caller's
// ALL scope grants them the authority to target any location in the company.
//
// AddMember is the canonical example: the request body carries the target
// employee's location(s), and the service validates each against the
// caller's allowed set — which, under ALL scope, is the entire company.
//
// RULE OF THUMB: only add an entry here if the endpoint's service layer
// re-validates every location it writes to. Never add a blanket "any write"
// allowance — each entry is a deliberate security decision.
var allScopeWritePOSTSuffixes = []string{
	"/rbac/members",
	// add more here as per-target-validating write endpoints are introduced
}

// isReadOnlyPost reports whether r is a POST that should be treated as a read
// for the purposes of the ALL-location guard.
func isReadOnlyPost(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	p := r.URL.Path
	for _, suffix := range readOnlyPOSTSuffixes {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

// isAllScopeWritePost reports whether r is a POST that is explicitly allowed
// to run under the company-wide ("ALL") scope, despite mutating state.
func isAllScopeWritePost(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	p := r.URL.Path
	for _, suffix := range allScopeWritePOSTSuffixes {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

// LocationValidationMiddleware normalizes X-Location-ID into a well-defined
// organizational context and enforces access control.
//
// Contract:
//   - Non-admin requests MUST send X-Location-ID.
//   - Value is either a location UUID, or the literal "ALL".
//   - "ALL" requires location_scope == ALL.
//   - "ALL" is rejected for writes, UNLESS the endpoint's path suffix
//     appears in allScopeWritePOSTSuffixes — in which case the endpoint is
//     trusted to re-validate every target location itself.
//   - On success, the request context gains:
//     location_mode          → "LOCATION" | "ALL"
//     validated_location_id  → uuid.UUID (uuid.Nil when mode == "ALL")
//     location_access_level  → "VIEW" | "MANAGE"
//
// The strings written into the context are the same ones read by
// locationctx.FromContext. Do not modify them here — modify
// locationctx.CtxMode / CtxLocationID / CtxAccessLevel.
func LocationValidationMiddleware(locationService *service.LocationService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// ---------------------------------------------------------------
			// 1. Admin bypass — checked before the header requirement.
			// ---------------------------------------------------------------
			if sessionType, _ := ctx.Value("session_type").(string); sessionType == "admin" {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			if claims, ok := ctx.Value("jwt_claims").(*models.JWTClaims); ok &&
				claims != nil && claims.SessionType == "admin" {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// ---------------------------------------------------------------
			// 2. Header must be present.
			// ---------------------------------------------------------------
			rawHeader := strings.TrimSpace(r.Header.Get("X-Location-ID"))
			if rawHeader == "" {
				util.JSONError(w, http.StatusBadRequest, "X-Location-ID header required")
				return
			}

			// ---------------------------------------------------------------
			// 3. Resolve identity + scope once (claims preferred, ctx fallback).
			// ---------------------------------------------------------------
			var (
				userID    uuid.UUID
				companyID uuid.UUID
				primaryID uuid.UUID
				scope     string
			)

			if claims, ok := ctx.Value("jwt_claims").(*models.JWTClaims); ok && claims != nil {
				userID, _ = uuid.Parse(claims.UserID)
				companyID, _ = uuid.Parse(claims.CompanyID)
				if claims.PrimaryLocationID != "" {
					primaryID, _ = uuid.Parse(claims.PrimaryLocationID)
				}
				scope = claims.LocationScope
			} else {
				userID, _ = uuid.Parse(stringFromCtx(ctx, "user_id"))
				companyID, _ = uuid.Parse(stringFromCtx(ctx, "company_id"))
				primaryID, _ = uuid.Parse(stringFromCtx(ctx, "primary_location_id"))
				scope = stringFromCtx(ctx, "location_scope")
			}

			if userID == uuid.Nil || companyID == uuid.Nil {
				util.JSONError(w, http.StatusUnauthorized, "user or company not in context")
				return
			}

			// ---------------------------------------------------------------
			// 4. Classify the HTTP method. GET/HEAD/OPTIONS are reads.
			//    A small allow-list of POST endpoints are also reads — they
			//    accept a body (batch fetch by IDs) but do not mutate state.
			// ---------------------------------------------------------------
			isWrite := r.Method != http.MethodGet &&
				r.Method != http.MethodHead &&
				r.Method != http.MethodOptions &&
				!isReadOnlyPost(r)

			// ---------------------------------------------------------------
			// 5. Company-wide ("ALL") context.
			// ---------------------------------------------------------------
			if strings.EqualFold(rawHeader, AllLocationsSentinel) {
				if scope != models.LocationScopeAll {
					util.JSONError(w, http.StatusForbidden,
						"company-wide view not permitted for this user")
					return
				}

				// Writes are rejected UNLESS the endpoint is explicitly
				// allow-listed as a per-target-validating write. The
				// endpoint's service layer is responsible for validating
				// every location it writes to against the caller's scope.
				if isWrite && !isAllScopeWritePost(r) {
					util.JSONError(w, http.StatusBadRequest,
						"company-wide context cannot be used for write operations")
					return
				}

				ctx = context.WithValue(ctx, locationctx.CtxMode, string(locationctx.ScopeAll))
				ctx = context.WithValue(ctx, locationctx.CtxLocationID, uuid.Nil)
				ctx = context.WithValue(ctx, locationctx.CtxAccessLevel, locationctx.AccessManage)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// ---------------------------------------------------------------
			// 6. Concrete location context.
			// ---------------------------------------------------------------
			requestedLoc, err := uuid.Parse(rawHeader)
			if err != nil || requestedLoc == uuid.Nil {
				util.JSONError(w, http.StatusBadRequest, "invalid X-Location-ID format")
				return
			}

			allowed, accessLevel, err := locationService.IsLocationAllowed(
				ctx, companyID, userID, requestedLoc, scope, primaryID,
			)
			if err != nil {
				util.JSONError(w, http.StatusInternalServerError, "location validation error")
				return
			}
			if !allowed {
				util.JSONError(w, http.StatusForbidden, "location not allowed for this user")
				return
			}
			if isWrite && accessLevel != models.AccessLevelManage {
				util.JSONError(w, http.StatusForbidden, "write access denied for this location")
				return
			}

			ctx = context.WithValue(ctx, locationctx.CtxMode, string(locationctx.ScopeLocation))
			ctx = context.WithValue(ctx, locationctx.CtxLocationID, requestedLoc)
			ctx = context.WithValue(ctx, locationctx.CtxAccessLevel, accessLevel)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// stringFromCtx is a small helper to safely pull a string out of context.
func stringFromCtx(ctx context.Context, key string) string {
	if s, ok := ctx.Value(key).(string); ok {
		return s
	}
	return ""
}
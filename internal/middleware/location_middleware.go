package middleware

import (
	"context"
	"fmt"
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
	"/hr/employees",

	// add more here as batch-read endpoints are introduced
}

// allScopeWriteRoots lists RESOURCE ROOTS whose write endpoints
// (POST/PUT/PATCH/DELETE) may run under the company-wide ("ALL") scope.
//
// A request path is allowed if, after stripping a trailing resource id
// (a UUID segment), the path ends with one of these roots. This means:
//
//	POST   /attendance/scheduling/calendars           → allowed
//	PUT    /attendance/scheduling/calendars/{uuid}    → allowed
//	DELETE /attendance/scheduling/calendars/{uuid}    → allowed
//	POST   /attendance/scheduling/holidays/process    → allowed
//	PUT    /attendance/scheduling/calendars/{uuid}/x  → REJECTED (nested path)
//
// RULE OF THUMB — only add an entry here when BOTH conditions hold:
//
//	(a) the endpoint legitimately supports a company-wide target
//	    (i.e. "no specific location"), AND
//	(b) the endpoint's handler re-validates every location it writes to
//	    against the caller's scope via locationctx / assertCanTouchLocation.
//
// Adding an entry here is a deliberate security decision. Never add a
// blanket "any write" allowance. If in doubt, leave it out and require the
// caller to send a concrete X-Location-ID.
var allScopeWriteRoots = []string{
	// RBAC: the request body carries every target employee's location(s);
	// the service validates each against the caller's allowed set, which
	// under ALL scope is the whole company.
	"/rbac/members",

	// Scheduling — creates and updates that support company-wide targets.
	//
	// The handler decides the effective location via resolveTargetLocation()
	// for creates, and assertCanTouchLocation() for updates / deletes.
	// ScopeAll callers may pass nil (company-wide) on create; on update the
	// row's own location_id is checked, and ScopeAll passes trivially.
	"/attendance/scheduling/calendars",
	"/attendance/scheduling/templates",

	// Adding a holiday targets an existing calendar. The handler loads the
	// calendar and verifies the caller can touch its scope before writing.
	"/attendance/scheduling/holidays",

	// Processing a holiday for a date cancels instances across the whole
	// company — inherently a company-wide operation.
	"/attendance/scheduling/holidays/process",
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

// isAllScopeWriteRequest reports whether r is a mutating request (POST, PUT,
// PATCH, DELETE) that is explicitly allowed to run under the company-wide
// ("ALL") scope, despite mutating state.
//
// Path matching:
//  1. If the path ends in /{uuid}, that segment is stripped before matching.
//     This lets a single root like "/attendance/scheduling/calendars" match
//     both POST /calendars and PUT /calendars/{uuid}.
//  2. Action segments that don't look like UUIDs (e.g. "process") are NOT
//     stripped, so "/attendance/scheduling/holidays/process" matches as-is.
func isAllScopeWriteRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		// proceed
	default:
		return false
	}

	p := r.URL.Path

	// Strip a trailing /{uuid} if present. Idempotent for action paths —
	// "process" is not a UUID so nothing is stripped for those.
	if i := strings.LastIndex(p, "/"); i >= 0 {
		tail := p[i+1:]
		if looksLikeUUID(tail) {
			p = p[:i]
		}
	}

	for _, root := range allScopeWriteRoots {
		if strings.HasSuffix(p, root) {
			return true
		}
	}
	return false
}

// looksLikeUUID does a cheap structural check: 36 chars, hyphens at
// positions 8/13/18/23, hex digits elsewhere. We do NOT require a valid
// UUID parse — we only need to distinguish "this is a resource id" from
// "this is an action segment like 'process'".
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') ||
				(c >= 'a' && c <= 'f') ||
				(c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// LocationValidationMiddleware normalizes X-Location-ID into a well-defined
// organizational context and enforces access control.
//
// Contract:
//   - Non-admin requests MUST send X-Location-ID.
//   - Value is either a location UUID, or the literal "ALL".
//   - "ALL" requires location_scope == ALL.
//   - "ALL" is rejected for writes, UNLESS the endpoint's path matches
//     allScopeWriteRoots — in which case the endpoint is trusted to
//     re-validate every target location itself.
//   - On success, the request context gains:
//     locationctx.CtxMode         → ScopeAll | ScopeLocation
//     locationctx.CtxLocationID   → uuid.UUID (uuid.Nil when Mode == ScopeAll)
//     locationctx.CtxAccessLevel  → VIEW | MANAGE
//
// The middleware never guesses the effective location for a write. It only
// answers: "is the caller permitted to enter this location context for this
// request?" The handler is responsible for deciding which location it will
// write to, and for rejecting a body that contradicts the context.
func LocationValidationMiddleware(
	locationService *service.LocationService,
) func(http.Handler) http.Handler {
	if locationService == nil {
		// Fail at wire time so the misconfiguration is caught during boot,
		// not on the first request that reaches this middleware.
		panic("middleware.LocationValidationMiddleware: locationService is nil")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// ---------------------------------------------------------------
			// 1. Admin bypass — checked before the header requirement.
			//
			// Admin sessions are cross-tenant and don't carry a location.
			// The rest of the pipeline is responsible for scoping what an
			// admin may do.
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
			if scope == "" {
				// No scope on the principal means we cannot reason about
				// location access at all. Fail closed rather than defaulting
				// to a permissive mode.
				util.JSONError(w, http.StatusForbidden, "location scope missing for user")
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
				if isWrite && !isAllScopeWriteRequest(r) {
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

			allowed, accessLevel, err := safeIsLocationAllowed(
				locationService,
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

// safeIsLocationAllowed wraps LocationService.IsLocationAllowed in a recover
// so a panic in the resolver chain (bad Redis state, malformed SQL row, etc.)
// produces a clean 500 instead of crashing the HTTP server goroutine.
func safeIsLocationAllowed(
	locationService *service.LocationService,
	ctx context.Context,
	companyID, userID, locationID uuid.UUID,
	scope string,
	primaryID uuid.UUID,
) (allowed bool, accessLevel string, err error) {
	defer func() {
		if r := recover(); r != nil {
			allowed = false
			accessLevel = ""
			err = fmt.Errorf("panic in IsLocationAllowed: %v", r)
		}
	}()
	return locationService.IsLocationAllowed(
		ctx, companyID, userID, locationID, scope, primaryID,
	)
}

// stringFromCtx is a small helper to safely pull a string out of context.
func stringFromCtx(ctx context.Context, key string) string {
	if s, ok := ctx.Value(key).(string); ok {
		return s
	}
	return ""
}

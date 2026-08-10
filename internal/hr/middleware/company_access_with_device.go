package middleware

import (
	"auth-service/internal/service"
	"auth-service/internal/util"
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func CompanyAccessMiddlewareWithDeviceSupport(
	jwtService *service.JWTService,
) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			ctx := r.Context()

			// Session type (MUST exist)
			sessionType, ok := ctx.Value("session_type").(string)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "Session type missing")
				return
			}

			// DEVICE SESSION (TRUST TOKEN CONTEXT)
			if sessionType == "device" {
				if _, ok := ctx.Value("company_id").(uuid.UUID); !ok {
					util.JSONError(w, http.StatusUnauthorized, "device company context missing")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// USER / ADMIN SESSION
			companyIDStr := chi.URLParam(r, "companyID")
			companyID, err := uuid.Parse(companyIDStr)
			if err != nil {
				util.JSONError(w, http.StatusBadRequest, "Invalid company ID")
				return
			}

			userIDStr, ok := ctx.Value("user_id").(string)
			if !ok {
				util.JSONError(w, http.StatusUnauthorized, "User not authenticated")
				return
			}

			userID, err := uuid.Parse(userIDStr)
			if err != nil {
				util.JSONError(w, http.StatusBadRequest, "Invalid user ID")
				return
			}

			// Admin bypass
			if sessionType == "admin" {
				ctx = context.WithValue(ctx, "company_id", companyID)
				ctx = context.WithValue(ctx, "current_user_id", userID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Normal user: enforce validated company
			validatedCompanyID, ok := ctx.Value("validated_company_id").(string)
			if !ok {
				util.JSONError(w, http.StatusForbidden, "Company access denied")
				return
			}

			validatedUUID, err := uuid.Parse(validatedCompanyID)
			if err != nil || validatedUUID != companyID {
				util.JSONError(w, http.StatusForbidden, "Company access violation")
				return
			}

			ctx = context.WithValue(ctx, "company_id", companyID)
			ctx = context.WithValue(ctx, "current_user_id", userID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

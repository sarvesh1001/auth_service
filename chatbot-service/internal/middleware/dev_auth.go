package middleware

import (
	"context"
	"net/http"
)

func DevAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Inject fake user context
		ctx := context.WithValue(r.Context(), "user_id", "test-user-123")
		ctx = context.WithValue(ctx, "session_type", "admin")
		ctx = context.WithValue(ctx, "company_id", "company-xyz")
		ctx = context.WithValue(ctx, "permission_mask", 999999)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

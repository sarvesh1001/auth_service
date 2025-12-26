package middleware

import (
    "context"
    "encoding/json"
    "net/http"
    "strings"

    "auth-service/internal/models"
    "auth-service/internal/service"
    "auth-service/internal/util"

    "go.uber.org/zap"
)

func parseBearerToken(r *http.Request, logger *zap.Logger) (string, bool) {
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        logger.Warn("Missing Authorization header")
        return "", false
    }

    fields := strings.Fields(authHeader)
    if len(fields) < 2 || !strings.EqualFold(fields[0], "Bearer") {
        logger.Warn("Invalid Authorization header format", zap.String("header", authHeader))
        return "", false
    }

    tokenStr := strings.Join(fields[1:], " ")
    tokenStr = strings.TrimSpace(strings.Trim(tokenStr, `"`))
    
    if strings.Count(tokenStr, ".") != 2 {
        logger.Warn("Malformed JWT token", zap.Int("dot_count", strings.Count(tokenStr, ".")))
        return "", false
    }

    return tokenStr, true
}

func JWTAuthMiddlewareWithRedis(sessionService *service.SessionService, logger *zap.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            tokenStr, ok := parseBearerToken(r, logger)
            if !ok {
                util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
                return
            }

            claims, err := sessionService.ValidateAccessToken(r.Context(), tokenStr)
            if err != nil {
                logger.Warn("JWT validation failed",
                    util.ErrorField(err),
                    util.String("token", util.MaskString(tokenStr, 8)))
                util.JSONError(w, http.StatusUnauthorized, "invalid, expired, or revoked token")
                return
            }

            ctx := r.Context()
            ctx = context.WithValue(ctx, "user_id", claims.UserID)
            ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
            ctx = context.WithValue(ctx, "role", claims.Role)
            ctx = context.WithValue(ctx, "session_type", claims.SessionType)
            ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
            ctx = context.WithValue(ctx, "jti", claims.JTI)
            ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)

            // IMPORTANT: We no longer override admin permission masks with full access
            // The permission mask from JWT claims now contains the actual admin permissions
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func AdminJWTAuthMiddleware(sessionService *service.SessionService, logger *zap.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            tokenStr, ok := parseBearerToken(r, logger)
            if !ok {
                util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
                return
            }

            claims, err := sessionService.ValidateAccessToken(r.Context(), tokenStr)
            if err != nil {
                logger.Warn("JWT validation failed", util.ErrorField(err))
                util.JSONError(w, http.StatusUnauthorized, "invalid, expired, or revoked token")
                return
            }

            if claims.SessionType != "admin" {
                util.JSONError(w, http.StatusForbidden, "access denied: admin session required")
                return
            }

            ctx := context.WithValue(r.Context(), "admin_id", claims.UserID)
            ctx = context.WithValue(ctx, "user_id", claims.UserID) // Also set user_id for compatibility
            ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
            ctx = context.WithValue(ctx, "role", claims.Role)
            ctx = context.WithValue(ctx, "session_type", claims.SessionType)
            ctx = context.WithValue(ctx, "jti", claims.JTI)
            ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
            
            // CRITICAL FIX: Use the actual permission mask from claims
            // This now contains the real admin permissions from GetAdminPermissionBitmask
            ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)

            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func AdminRoleMiddleware(requiredRole string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            userRole, ok := r.Context().Value("role").(string)
            if !ok {
                util.JSONError(w, http.StatusForbidden, "role not found in context")
                return
            }

            userRoleLevel := getRoleLevel(userRole)
            requiredRoleLevel := getRoleLevel(requiredRole)

            if userRoleLevel < requiredRoleLevel {
                util.JSONError(w, http.StatusForbidden, "insufficient admin privileges")
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

func getRoleLevel(role string) int {
    switch role {
    case models.RoleAdminSuperAdmin:
        return 3
    case models.RoleAdminManager:
        return 2
    case models.RoleAdminEmployee:
        return 1
    case models.RoleUserOwner:
        return 3
    case models.RoleUserSuperEmployee:
        return 2
    case models.RoleUserEmployee:
        return 1
    default:
        return 0
    }
}

func UserAuthMiddleware(sessionService *service.SessionService, logger *zap.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            tokenStr, ok := parseBearerToken(r, logger)
            if !ok {
                util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
                return
            }

            claims, err := sessionService.ValidateAccessToken(r.Context(), tokenStr)
            if err != nil {
                logger.Warn("JWT validation failed", util.ErrorField(err))
                util.JSONError(w, http.StatusUnauthorized, "invalid, expired, or revoked token")
                return
            }

            if claims.SessionType != "user" {
                util.JSONError(w, http.StatusForbidden, "access denied: user session required")
                return
            }

            ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
            ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
            ctx = context.WithValue(ctx, "role", claims.Role)
            ctx = context.WithValue(ctx, "session_type", claims.SessionType)
            ctx = context.WithValue(ctx, "jti", claims.JTI)
            ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
            ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)
            
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func JWTAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                respondWithJWTError(w, logger, http.StatusUnauthorized, "Missing authorization header")
                return
            }

            parts := strings.Split(authHeader, " ")
            if len(parts) != 2 || parts[0] != "Bearer" {
                respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid authorization header")
                return
            }

            accessToken := parts[1]
            claims, err := jwtService.ValidateAccessToken(r.Context(), accessToken)
            if err != nil {
                logger.Warn("Invalid JWT token", zap.Error(err))
                respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid or expired token")
                return
            }

            ctx := r.Context()
            ctx = context.WithValue(ctx, "user_id", claims.UserID)
            ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
            ctx = context.WithValue(ctx, "session_type", claims.SessionType)
            ctx = context.WithValue(ctx, "jti", claims.JTI)
            
            if claims.CompanyID != "" {
                ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
            }
            
            if claims.PermissionMask != nil {
                ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)
            }

            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func respondWithJWTError(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string) {
    if logger != nil {
        logger.Warn("JWT auth error",
            zap.Int("status_code", statusCode),
            zap.String("message", message),
        )
    }
    
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    _ = json.NewEncoder(w).Encode(map[string]interface{}{
        "success": false,
        "error":   message,
        "message": "Authentication failed",
        "code":    statusCode,
    })
}

// AdminPermissionMiddleware is a specialized middleware for admin permission checks
func AdminPermissionMiddleware(requiredPermission string, logger *zap.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            sessionType, ok := r.Context().Value("session_type").(string)
            if !ok || sessionType != "admin" {
                util.JSONError(w, http.StatusForbidden, "admin session required")
                return
            }

            permissionMask, ok := r.Context().Value("permission_mask").([]uint64)
            if !ok || permissionMask == nil {
                adminID, _ := r.Context().Value("admin_id").(string)
                logger.Warn("Permission mask not found for admin",
                    util.String("admin_id", adminID))
                util.JSONError(w, http.StatusForbidden, "permission mask not found")
                return
            }

            role, _ := r.Context().Value("role").(string)
            adminID, _ := r.Context().Value("admin_id").(string)

            // Super admin bypass - they have all permissions
            if role == models.RoleAdminSuperAdmin {
                logger.Debug("Super admin permission bypass",
                    util.String("admin_id", adminID),
                    util.String("required_permission", requiredPermission))
                next.ServeHTTP(w, r)
                return
            }

            // Check permission using the actual mask
            if !hasAdminPermission(permissionMask, requiredPermission) {
                logger.Warn("Admin permission denied",
                    util.String("admin_id", adminID),
                    util.String("role", role),
                    util.String("required_permission", requiredPermission),
                    util.Any("permission_mask", permissionMask))
                util.JSONError(w, http.StatusForbidden, "insufficient admin permissions")
                return
            }

            logger.Debug("Admin permission granted",
                util.String("admin_id", adminID),
                util.String("permission", requiredPermission))
            
            next.ServeHTTP(w, r)
        })
    }
}

func hasAdminPermission(mask []uint64, permission string) bool {
    // This should use your RBAC package's HasPermission function
    // For now, using a placeholder - make sure to import and use your rbac package
    if mask == nil || len(mask) == 0 {
        return false
    }
    
    // TODO: Replace with actual RBAC check using your rbac package
    // return rbac.HasPermission(mask, permission)
    
    // For testing, super admin always has permission
    return false // Default to false - implement properly with your RBAC
}

// CombinedMiddleware combines JWT auth with session validation
func CombinedMiddleware(
    sessionService *service.SessionService,
    logger *zap.Logger,
) func(http.Handler) http.Handler {
    jwtAuth := JWTAuthMiddlewareWithRedis(sessionService, logger)
    sessionValidation := SessionValidationMiddleware(sessionService, logger)
    
    return func(next http.Handler) http.Handler {
        return jwtAuth(sessionValidation(next))
    }
}

// CombinedAdminMiddleware combines admin JWT auth with session validation
func CombinedAdminMiddleware(
    sessionService *service.SessionService,
    logger *zap.Logger,
) func(http.Handler) http.Handler {
    adminAuth := AdminJWTAuthMiddleware(sessionService, logger)
    sessionValidation := SessionValidationMiddleware(sessionService, logger)
    
    return func(next http.Handler) http.Handler {
        return adminAuth(sessionValidation(next))
    }
}

// AdminRoleOrPermissionMiddleware checks either role or permission
func AdminRoleOrPermissionMiddleware(
    minRole string,
    requiredPermission string,
    sessionService *service.SessionService,
    logger *zap.Logger,
) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // First authenticate
            tokenStr, ok := parseBearerToken(r, logger)
            if !ok {
                util.JSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
                return
            }

            claims, err := sessionService.ValidateAccessToken(r.Context(), tokenStr)
            if err != nil {
                logger.Warn("JWT validation failed", util.ErrorField(err))
                util.JSONError(w, http.StatusUnauthorized, "invalid, expired, or revoked token")
                return
            }

            if claims.SessionType != "admin" {
                util.JSONError(w, http.StatusForbidden, "access denied: admin session required")
                return
            }

            // Check role level
            userRoleLevel := getRoleLevel(claims.Role)
            requiredRoleLevel := getRoleLevel(minRole)
            
            // If role is sufficient, allow access
            if userRoleLevel >= requiredRoleLevel {
                ctx := buildContext(r.Context(), claims)
                next.ServeHTTP(w, r.WithContext(ctx))
                return
            }

            // If role is insufficient, check permission
            if claims.PermissionMask == nil || len(claims.PermissionMask) == 0 {
                util.JSONError(w, http.StatusForbidden, "insufficient permissions")
                return
            }

            if !hasAdminPermission(claims.PermissionMask, requiredPermission) {
                util.JSONError(w, http.StatusForbidden, "insufficient permissions")
                return
            }

            // Permission granted
            ctx := buildContext(r.Context(), claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func buildContext(ctx context.Context, claims *models.JWTClaims) context.Context {
    ctx = context.WithValue(ctx, "admin_id", claims.UserID)
    ctx = context.WithValue(ctx, "user_id", claims.UserID)
    ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
    ctx = context.WithValue(ctx, "role", claims.Role)
    ctx = context.WithValue(ctx, "session_type", claims.SessionType)
    ctx = context.WithValue(ctx, "jti", claims.JTI)
    ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
    ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)
    return ctx
}
package handler

import (
    authMiddleware "auth-service/internal/middleware"
    "auth-service/internal/service"
    "context"
    "encoding/json"
    "net/http"
    "strings"
    "time"

    "github.com/go-chi/chi/v5"
    chiMiddleware "github.com/go-chi/chi/v5/middleware"
    "github.com/go-chi/cors"
    "github.com/google/uuid"
    "go.uber.org/zap"
)

func NewRouter(
    otpHandler *OTPHandler,
    adminHandler *AdminHandler,
    authHandler *AuthHandler,
    rbacHandler *RBACHandler,
    pairingHandler *PairingHandler,
    wsHandler *WebSocketHandler,
    sessionService *service.SessionService,
    jwtService *service.JWTService,
    logger *zap.Logger,
) chi.Router {
    router := chi.NewRouter()

    // ============================================================
    // GLOBAL MIDDLEWARES
    // ============================================================
    // router.Use(requireHTTPS)
    router.Use(chiMiddleware.RequestID)
    router.Use(chiMiddleware.RealIP)
    router.Use(LoggerMiddleware(logger))
    router.Use(chiMiddleware.Recoverer)
    router.Use(chiMiddleware.Timeout(60 * time.Second))

    // CORS - Add required headers
    router.Use(cors.Handler(cors.Options{
        AllowedOrigins:   []string{"https://*", "http://localhost:3000", "http://localhost:8080"},
        AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
        AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", 
            "X-Session-Type", "X-Device-ID", "X-Company-ID"},
        AllowCredentials: true,
        MaxAge:           300,
    }))

    // ============================================================
    // HEALTH CHECK
    // ============================================================
    router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
        logger.Info("Health check requested")
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(map[string]string{
            "status":  "healthy",
            "service": "auth-service",
            "time":    time.Now().UTC().Format(time.RFC3339),
        })
    })

    // ============================================================
    // MAIN API
    // ============================================================
    router.Route("/api/v1", func(r chi.Router) {

        //-----------------------------------------------------------
        // PUBLIC ROUTES
        //-----------------------------------------------------------
        authHandler.RegisterPublicRoutes(r)
        authHandler.RegisterUserPublicRoutes(r)
        otpHandler.RegisterRoutes(r)

        //-----------------------------------------------------------
        // ADMIN AUTH (PUBLIC)
        //-----------------------------------------------------------
        adminHandler.RegisterRoutes(r)

        //-----------------------------------------------------------
        // WEB LOGIN (QR PAIRING) ROUTES
        //-----------------------------------------------------------
        r.Route("/web/login", func(r chi.Router) {
            r.Get("/qr", pairingHandler.GenerateQR)
            r.Get("/status", pairingHandler.Status)
            r.Post("/confirm", pairingHandler.Confirm)
            r.Get("/ws", pairingHandler.WebSocket)

            // Mobile pairing (requires JWT + Session Validation)
            r.With(
                authMiddleware.JWTAuthMiddlewareWithRedis(sessionService, logger),
                authMiddleware.SessionValidationMiddleware(sessionService, logger),
            ).Post("/pair", pairingHandler.Pair)
        })

        //-----------------------------------------------------------
        // PROTECTED ROUTES (JWT + SESSION VALIDATION REQUIRED)
        //-----------------------------------------------------------
        r.Group(func(r chi.Router) {
            // JWT Middleware (parses token and adds claims to context)
            r.Use(authMiddleware.JWTAuthMiddlewareWithRedis(sessionService, logger))
            
            // 🔥 NEW: Session Validation Middleware (performs all security checks)
            r.Use(authMiddleware.SessionValidationMiddleware(sessionService, logger))

            //-----------------------------------------------------------
            // USER AUTH PROTECTED ROUTES
            //-----------------------------------------------------------
            authHandler.RegisterProtectedRoutes(r)

            //-----------------------------------------------------------
            // COMPANY EMPLOYEE SEARCH ROUTES
            //-----------------------------------------------------------
            r.Route("/companies/{companyID}/employees", func(r chi.Router) {
                // Use EnhancedCompanyAccessMiddleware which checks JWT company ID
                r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))
                
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
                    Post("/search", authHandler.SearchCompanyEmployees)
                    
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
                    Get("/search/advanced", authHandler.SearchCompanyEmployeesAdvanced)
                    
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
                    Get("/search/suggestions", authHandler.GetCompanyEmployeeSuggestions)
                    
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
                    Get("/suggestions", authHandler.GetCompanyEmployeeSuggestions)
                    
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
                    Get("/username/{username}", authHandler.FindCompanyEmployeeByUsername)
            })

            //-----------------------------------------------------------
            // COMPANY OWNER ROUTES (NON-ADMIN COMPANY OWNERS)
            //-----------------------------------------------------------
            r.Route("/companies/{companyID}", func(r chi.Router) {
                r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

                r.Get("/", adminHandler.GetCompany)
                r.Get("/getemployees", adminHandler.GetCompanyEmployees)
                r.Get("/departments", adminHandler.GetCompanyDepartments)
                r.Get("/roles", adminHandler.GetCompanyRoles)
                r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)
                r.Get("/stats", adminHandler.GetCompanyStats)

                // Owner-only operations
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.create", logger)).
                    Post("/departments/create", rbacHandler.CreateDepartment)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
                    Put("/employees/{userID}/role", adminHandler.UpdateEmployeeRole)
            })

            //-----------------------------------------------------------
            // COMPANY RBAC ROUTES
            //-----------------------------------------------------------
            r.Route("/companies/{companyID}/rbac", func(r chi.Router) {
                r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

                // ===============================
                // ROLE MANAGEMENT
                // ===============================
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.create", logger)).
                    Post("/roles", rbacHandler.CreateRole)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
                    Get("/roles", rbacHandler.ListRoles)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
                    Get("/roles/{roleID}", rbacHandler.GetRole)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
                    Put("/roles/{roleID}", rbacHandler.UpdateRole)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.delete", logger)).
                    Delete("/roles/{roleID}", rbacHandler.DeleteRole)

                // Employee Management
                r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
                    Post("/employees", rbacHandler.AddEmployee)

                // Manager Management
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
                    Post("/managers", rbacHandler.AddManager)

                // Available Permissions
                r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
                    Get("/available-permissions", rbacHandler.GetAvailablePermissions)

                // ===============================
                // PERMISSION MANAGEMENT
                // ===============================
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
                    Post("/roles/{roleID}/permissions", rbacHandler.AssignPermissionsToRole)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
                    Delete("/roles/{roleID}/permissions", rbacHandler.RemovePermissionsFromRole)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
                    Get("/roles/{roleID}/permissions", rbacHandler.GetRolePermissions)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
                    Put("/roles/{roleID}/permissions", rbacHandler.ReplaceRolePermissions)

                // ===============================
                // GLOBAL PERMISSION QUERIES
                // ===============================
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
                    Get("/permissions", rbacHandler.ListAllPermissions)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
                    Get("/permissions/module/{module}", rbacHandler.ListPermissionsByModule)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
                    Get("/permissions/name/{permissionName}", rbacHandler.GetPermissionByName)

                // ===============================
                // DEPARTMENT MANAGEMENT
                // ===============================
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
                    Get("/departments", rbacHandler.ListDepartments)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
                    Put("/departments/{departmentID}", rbacHandler.UpdateDepartment)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
                    Put("/departments/{departmentID}/rename", rbacHandler.RenameDepartment)

                // ===============================
                // USER PERMISSIONS & HIERARCHY
                // ===============================
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
                    Get("/users/{userID}/permissions", rbacHandler.GetUserPermissions)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
                    Get("/users/{userID}/permissions/bitmask", rbacHandler.GetUserPermissionBitmask)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
                    Get("/users/{userID}/permissions/check", rbacHandler.CheckUserPermission)

                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
                    Get("/users/{userID}/hierarchy", rbacHandler.GetUserHierarchy)

                // ===============================
                // BULK ROLE ASSIGNMENT
                // ===============================
                r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.role.assign", logger)).
                    Post("/bulk-assign", rbacHandler.BulkAssignRoles)
            })

            //-----------------------------------------------------------
            // ADMIN PROTECTED ROUTES (WITH ADMIN SESSION CHECK)
            //-----------------------------------------------------------
            r.Route("/admin", func(r chi.Router) {
                // Admin session type check
                r.Use(AdminSessionMiddleware(logger))

                // 🔥 NEW BITMASK ADMIN ROUTES WITH DEPARTMENT SUPPORT
                r.Route("/admins", func(r chi.Router) {
                    // Admin stats
                    r.Get("/stats", adminHandler.GetStats)
                    
                    // ===== DEPARTMENT-BASED ADMIN MANAGEMENT =====
                    // Invite admin with departments and permissions (NEW)
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.create", logger)).
                        Post("/invite-with-departments", adminHandler.InviteAdminWithDepartments)
                    r.Get("/debug/permission-calculation", adminHandler.DebugPermissionCalculation)

                    // Update admin departments (NEW)
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.department.update", logger)).
                        Put("/{adminID}/departments", adminHandler.UpdateAdminDepartments)
                    
                    // Get admin with department details (NEW)
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
                        Get("/{adminID}/details", adminHandler.GetAdminWithDetails)
                    
                    // Check admin department access (NEW)
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
                        Get("/{adminID}/check-department-access", adminHandler.CheckAdminDepartmentAccess)
                    
                    // Get admins by department (NEW)
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
                        Get("/by-department/{departmentName}", adminHandler.GetAdminsByDepartment)
                    
                    // Phone management
                    r.Patch("/phone", adminHandler.ChangeOwnPhone)  // Change own phone
                    r.Patch("/{adminID}/phone", adminHandler.ChangeAdminPhone)  // Change other admin's phone
                    
                    // Admin invitation with bitmask
                    r.Post("/invite", adminHandler.InviteAdminWithBitmask)
                    
                    // Admin promotion with bitmask
                    r.Patch("/{adminID}/promote", adminHandler.PromoteAdminWithBitmask)
                    
                    // Get admins by role mask
                    r.Get("/role/{roleMask}", adminHandler.GetAdminsByRoleMask)
                    
                    // Admin CRUD operations
                    r.Get("/", adminHandler.ListAdmins)
                    r.Get("/{adminID}", adminHandler.GetAdminByID)
                    r.Get("/phone/{phone}", adminHandler.GetAdminByPhone)
                    r.Delete("/{adminID}", adminHandler.RemoveAdmin)
                    r.Patch("/{adminID}/deactivate", adminHandler.DeactivateAdmin)
                    r.Patch("/{adminID}/activate", adminHandler.ActivateAdmin)
                    
                    // ===== PERMISSION MANAGEMENT =====
                    r.Route("/{adminID}/permissions", func(r chi.Router) {
                        // Get permissions
                        r.Get("/", adminHandler.GetAdminPermissions)
                        r.Get("/mask", adminHandler.GetAdminPermissionMask)
                        r.Get("/check", adminHandler.CheckAdminPermission)
                        
                        // Permission operations
                        r.Post("/{permissionName}", adminHandler.GrantPermissionToAdmin)
                        r.Delete("/{permissionName}", adminHandler.RevokePermissionFromAdmin)
                        r.Post("/batch", adminHandler.BatchUpdatePermissions)
                    })
                })

                // ===== SYSTEM DEPARTMENT BITMASK UTILITIES =====
                r.Route("/departments", func(r chi.Router) {
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.department.view", logger)).
                        Get("/", adminHandler.GetSystemDepartments)
                    
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.department.view", logger)).
                        Get("/bitmask", adminHandler.GetSystemDepartmentsWithBitmask)
                })

                // System owner initialization (admin-only)
                r.Post("/init-owner", adminHandler.InitializeOwner)

                // Admin MPIN management
                r.Post("/mpin/change-by-admin", adminHandler.ChangeAdminMPINByAdmin)

                // User management
                r.Put("/users/update/{userID}", adminHandler.UpdateUser)
                r.Patch("/users/{userID}/kyc", adminHandler.UpdateUserKYC)
                r.Post("/users/{userID}/ban", adminHandler.BanUser)
                r.Post("/users/{userID}/unban", adminHandler.UnbanUser)
                r.Get("/users/banned", adminHandler.GetBannedUsers)

                // --------------------------------------------------------
                // SYSTEM / PERMISSIONS / COMPANY / EMPLOYEE / RBAC
                // --------------------------------------------------------
                r.Get("/debug/companies/{companyID}/departments", adminHandler.DebugCompanyDepartments)
                
                // Global permissions endpoints
                r.Route("/permissions", func(r chi.Router) {
                    r.Get("/", adminHandler.GetAllPermissions)
                    r.Get("/module/{module}", adminHandler.GetPermissionsByModule)
                })

                // ADVANCED USER SEARCH ENDPOINTS (ADMIN ONLY)
                r.Route("/users", func(r chi.Router) {
                    r.Get("/search", adminHandler.SearchUsers)
                    r.Get("/search/advanced", adminHandler.SearchUsersAdvanced)
                    r.Get("/search/suggestions", adminHandler.GetUserSuggestions)
                    r.Get("/search/username", adminHandler.SearchUsersByUsername)
                    r.Get("/search/fullname", adminHandler.SearchUsersByFullName)
                    r.Get("/recently-active", adminHandler.GetRecentlyActiveUsers)
                    r.Get("/kyc-status/{status}", adminHandler.ListUsersByKYCStatus)
                })

                // Company Management
                r.Route("/companies", func(r chi.Router) {
                    // CREATE COMPANY - requires admin.company.update (since creating is an update operation)
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
                        Post("/", adminHandler.CreateCompany)
                    
                    // LIST VIEW OPERATIONS - require admin.company.view
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                        Get("/status/{status}", adminHandler.GetCompaniesByStatus)
                    
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                        Get("/recent", adminHandler.GetRecentCompanies)
                    
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                        Get("/expiring-subscriptions", adminHandler.GetCompaniesWithExpiringSubscription)
                    
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                        Get("/tier/{tier}", adminHandler.GetCompaniesByTier)
                    
                    // SEARCH OPERATIONS - require admin.company.view
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                        Get("/search", adminHandler.SearchCompanies)
                    
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                        Get("/suggestions", adminHandler.GetCompanySuggestions)
                    
                    // OWNER SEARCH - requires admin.company.view
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                        Get("/search-by-owner/{ownerID}", adminHandler.SearchCompaniesByOwner)
                    
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                        Get("/owner/{ownerID}/search", adminHandler.SearchCompaniesByOwner)
                    
                    // ANALYTICS - requires admin.company.view
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                        Get("/search-analytics", adminHandler.GetCompanySearchAnalytics)
                    
                    // BENCHMARK - requires admin.company.update (modifying/search operations)
                    r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
                        Post("/search-benchmark", adminHandler.BenchmarkCompanySearch)
                    
                    // COMPANY-SPECIFIC ROUTES
                    r.Route("/{companyID}", func(r chi.Router) {
                        // VIEW COMPANY DETAILS - requires admin.company.view
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                            Get("/", adminHandler.GetCompany)
                        
                        // DEACTIVATE COMPANY - requires admin.company.suspend
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.suspend", logger)).
                            Patch("/deactivate", adminHandler.DeactivateCompany)
                        
                        // REACTIVATE COMPANY - requires admin.company.update
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
                            Patch("/activate", adminHandler.ReactivateCompany)
                        
                        // EXTEND SUBSCRIPTION - requires admin.company.update
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
                            Patch("/extend-subscription", adminHandler.ExtendSubscription)
                        
                        // UPDATE SUBSCRIPTION - requires admin.company.update
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
                            Patch("/subscription", adminHandler.UpdateSubscription)
                        
                        // VIEW STATS - requires admin.company.view
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                            Get("/stats", adminHandler.GetCompanyStats)
                        
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                            Get("/rbac-stats", adminHandler.GetCompanyRBACStats)
                        
                        // VIEW EMPLOYEES - requires admin.company.view
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                            Get("/employees", adminHandler.GetCompanyEmployees)
                        
                        // VIEW DEPARTMENTS - requires admin.company.view
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                            Get("/departments", adminHandler.GetCompanyDepartments)
                        
                        // VIEW ROLES - requires admin.company.view
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                            Get("/roles", adminHandler.GetCompanyRoles)
                        
                        // CREATE ROLE - requires admin.company.update
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
                            Post("/roles", rbacHandler.CreateRole)
                        
                        // VIEW HIERARCHY - requires admin.company.view
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
                            Get("/hierarchy", adminHandler.GetCompanyHierarchy)
                        
                        // BULK ASSIGN ROLES - requires admin.company.update
                        r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
                            Post("/employees/bulk-assign", adminHandler.BulkAssignRoles)
                    })
                })
                

                // Employee Management
                r.Route("/employees", func(r chi.Router) {
                    r.Route("/{userID}", func(r chi.Router) {
                        r.Put("/role", adminHandler.UpdateEmployeeRole)
                        r.Get("/permissions", adminHandler.GetEmployeePermissions)
                        r.Get("/hierarchy", adminHandler.GetUserHierarchy)
                    })
                    r.Post("/check-permission", adminHandler.CheckEmployeePermission)
                })

                // Role Permission Management
                r.Route("/roles", func(r chi.Router) {
                    r.Route("/{roleID}", func(r chi.Router) {
                        r.Post("/permissions", adminHandler.GrantRolePermissions)
                    })
                })

                // ===== LEGACY COMPATIBILITY ROUTES (remove after migration) =====
                // Keep these temporarily if you need backward compatibility
                r.Get("/admins/role/{roleLevel}", adminHandler.GetAdminsByRoleMask)  // Legacy string-based
                r.Get("/admins/status/{status}", adminHandler.GetAdminsByStatus)
                
                // Legacy admin management routes (redirect to new ones)
                r.Patch("/owner/phone", func(w http.ResponseWriter, r *http.Request) {
                    // Redirect to new endpoint
                    adminHandler.ChangeOwnPhone(w, r)
                })
                r.Post("/invite", func(w http.ResponseWriter, r *http.Request) {
                    // Redirect to new bitmask endpoint
                    adminHandler.InviteAdminWithBitmask(w, r)
                })
            })
        })
    })

    // ============================================================
    // GLOBAL ERROR HANDLERS
    // ============================================================
    router.NotFound(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusNotFound)
        _ = json.NewEncoder(w).Encode(map[string]interface{}{
            "error":   "endpoint not found",
            "path":    r.URL.Path,
            "method":  r.Method,
            "service": "auth-service",
        })
    })

    router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusMethodNotAllowed)
        _ = json.NewEncoder(w).Encode(map[string]interface{}{
            "error":   "method not allowed",
            "path":    r.URL.Path,
            "method":  r.Method,
            "service": "auth-service",
        })
    })

    return router
}

// ============================================================================
// MIDDLEWARES
// ============================================================================

func AdminSessionMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            sessionType, ok := r.Context().Value("session_type").(string)
            if !ok || sessionType != "admin" {
                logger.Warn("Access denied: not an admin session",
                    zap.String("session_type", sessionType),
                    zap.String("path", r.URL.Path),
                )
                respondWithJWTError(w, logger, http.StatusForbidden, "Access denied: admin session required")
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

// Enhanced Company Access Middleware
func EnhancedCompanyAccessMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract company ID from URL params
            companyIDStr := chi.URLParam(r, "companyID")
            companyID, err := uuid.Parse(companyIDStr)
            if err != nil {
                respondWithJWTError(w, logger, http.StatusBadRequest, "Invalid company ID")
                return
            }

            // Get session type from context
            sessionType, ok := r.Context().Value("session_type").(string)
            if !ok {
                respondWithJWTError(w, logger, http.StatusUnauthorized, "Session type not found")
                return
            }

            // Get user ID from context
            userIDStr, ok := r.Context().Value("user_id").(string)
            if !ok {
                respondWithJWTError(w, logger, http.StatusUnauthorized, "User not authenticated")
                return
            }

            userID, err := uuid.Parse(userIDStr)
            if err != nil {
                respondWithJWTError(w, logger, http.StatusBadRequest, "Invalid user ID")
                return
            }

            // For non-admin users, check company access
            if sessionType != "admin" {
                // Get company ID from context (validated by session validation middleware)
                validatedCompanyID, ok := r.Context().Value("validated_company_id").(string)
                if !ok || validatedCompanyID == "" {
                    respondWithJWTError(w, logger, http.StatusForbidden, 
                        "Company access denied: No validated company context")
                    return
                }

                validatedCompanyUUID, err := uuid.Parse(validatedCompanyID)
                if err != nil {
                    respondWithJWTError(w, logger, http.StatusForbidden, 
                        "Company access denied: Invalid company ID in validated session")
                    return
                }

                // Verify the user is accessing their own company
                if validatedCompanyUUID != companyID {
                    logger.Warn("Company access violation",
                        zap.String("user_id", userID.String()),
                        zap.String("requested_company", companyID.String()),
                        zap.String("validated_company", validatedCompanyID),
                        zap.String("session_type", sessionType))
                    
                    respondWithJWTError(w, logger, http.StatusForbidden, 
                        "Company access denied: You can only access your own company")
                    return
                }

                logger.Debug("Company access verified for non-admin user",
                    zap.String("user_id", userID.String()),
                    zap.String("company_id", companyID.String()),
                    zap.String("session_type", sessionType))
            } else {
                logger.Debug("Admin user accessing company - no company restriction",
                    zap.String("admin_id", userID.String()),
                    zap.String("company_id", companyID.String()))
            }

            // Add company ID and user ID to context
            ctx := context.WithValue(r.Context(), "company_id", companyID)
            ctx = context.WithValue(ctx, "current_user_id", userID)

            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// Updated JWTAuthMiddlewareWithRedis to include bitmask handling
func JWTAuthMiddlewareWithRedis(sessionService *service.SessionService, logger *zap.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()

            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                respondWithJWTError(w, logger, http.StatusUnauthorized, "Missing authorization header")
                return
            }

            parts := strings.Split(authHeader, " ")
            if len(parts) != 2 || parts[0] != "Bearer" {
                respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid authorization header format")
                return
            }

            accessToken := parts[1]
            claims, err := sessionService.ValidateAccessToken(ctx, accessToken)
            if err != nil {
                logger.Warn("Invalid JWT token", zap.Error(err))
                respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid or expired token")
                return
            }

            // Add claims to context
            ctx = context.WithValue(ctx, "user_id", claims.UserID)
            ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
            ctx = context.WithValue(ctx, "role", claims.Role)
            ctx = context.WithValue(ctx, "session_type", claims.SessionType)
            ctx = context.WithValue(ctx, "jti", claims.JTI)

            // Include permission mask and company ID in context
            if claims.PermissionMask != nil {
                ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)
            }
            
            if claims.CompanyID != "" {
                ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
            }

            // Include bitmask-specific claims
            if claims.AdminRoleMask != 0 {
                ctx = context.WithValue(ctx, "admin_role_mask", claims.AdminRoleMask)
            }

            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()
            ww := chiMiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
            next.ServeHTTP(ww, r)

            logger.Info("HTTP request",
                zap.String("method", r.Method),
                zap.String("path", r.URL.Path),
                zap.String("query", r.URL.RawQuery),
                zap.String("remote_addr", r.RemoteAddr),
                zap.Int("status", ww.Status()),
                zap.Duration("duration", time.Since(start)),
                zap.String("user_agent", r.UserAgent()),
            )
        })
    }
}

func requireHTTPS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

        host := r.Host

        // Allow HTTP on local dev networks:
        if r.TLS == nil &&
            (strings.HasPrefix(host, "localhost") ||
                strings.HasPrefix(host, "127.0.0.1") ||
                strings.HasPrefix(host, "192.168.") ||
                strings.HasPrefix(host, "10.") ||
                strings.HasPrefix(host, "172.16.")) {

            next.ServeHTTP(w, r)
            return
        }

        // All other cases require HTTPS
        if r.TLS == nil {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusUpgradeRequired)
            _ = json.NewEncoder(w).Encode(map[string]string{"error": "https required"})
            return
        }

        next.ServeHTTP(w, r)
    })
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

// package handler

// import (
// 	authMiddleware "auth-service/internal/middleware"
// 	"auth-service/internal/service"
// 	"context"
// 	"encoding/json"
// 	"net/http"
// 	"strings"
// 	"time"

// 	"github.com/go-chi/chi/v5"
// 	chiMiddleware "github.com/go-chi/chi/v5/middleware"
// 	"github.com/go-chi/cors"
// 	"github.com/google/uuid"
// 	"go.uber.org/zap"
// )

// func NewRouter(
// 	otpHandler *OTPHandler,
// 	adminHandler *AdminHandler,
// 	authHandler *AuthHandler,
// 	rbacHandler *RBACHandler,
// 	pairingHandler *PairingHandler,
// 	wsHandler *WebSocketHandler,
// 	sessionService *service.SessionService,
// 	jwtService *service.JWTService,
// 	logger *zap.Logger,
// ) chi.Router {
// 	router := chi.NewRouter()

// 	// ============================================================
// 	// GLOBAL MIDDLEWARES
// 	// ============================================================
// 	// router.Use(requireHTTPS)
// 	router.Use(chiMiddleware.RequestID)
// 	router.Use(chiMiddleware.RealIP)
// 	router.Use(LoggerMiddleware(logger))
// 	router.Use(chiMiddleware.Recoverer)
// 	router.Use(chiMiddleware.Timeout(60 * time.Second))

// 	// CORS - Add required headers
// 	router.Use(cors.Handler(cors.Options{
// 		AllowedOrigins:   []string{"https://*", "http://localhost:3000", "http://localhost:8080"},
// 		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
// 		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", 
// 			"X-Session-Type", "X-Device-ID", "X-Company-ID"},
// 		AllowCredentials: true,
// 		MaxAge:           300,
// 	}))

// 	// ============================================================
// 	// HEALTH CHECK
// 	// ============================================================
// 	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
// 		logger.Info("Health check requested")
// 		w.Header().Set("Content-Type", "application/json")
// 		_ = json.NewEncoder(w).Encode(map[string]string{
// 			"status":  "healthy",
// 			"service": "auth-service",
// 			"time":    time.Now().UTC().Format(time.RFC3339),
// 		})
// 	})

// 	// ============================================================
// 	// MAIN API
// 	// ============================================================
// 	router.Route("/api/v1", func(r chi.Router) {

// 		//-----------------------------------------------------------
// 		// PUBLIC ROUTES
// 		//-----------------------------------------------------------
// 		authHandler.RegisterPublicRoutes(r)
// 		authHandler.RegisterUserPublicRoutes(r)
// 		otpHandler.RegisterRoutes(r)

// 		//-----------------------------------------------------------
// 		// ADMIN AUTH (PUBLIC)
// 		//-----------------------------------------------------------
// 		adminHandler.RegisterRoutes(r)

// 		//-----------------------------------------------------------
// 		// WEB LOGIN (QR PAIRING) ROUTES
// 		//-----------------------------------------------------------
// 		r.Route("/web/login", func(r chi.Router) {
// 			r.Get("/qr", pairingHandler.GenerateQR)
// 			r.Get("/status", pairingHandler.Status)
// 			r.Post("/confirm", pairingHandler.Confirm)
// 			r.Get("/ws", pairingHandler.WebSocket)

// 			// Mobile pairing (requires JWT + Session Validation)
// 			r.With(
// 				authMiddleware.JWTAuthMiddlewareWithRedis(sessionService, logger),
// 				authMiddleware.SessionValidationMiddleware(sessionService, logger),
// 			).Post("/pair", pairingHandler.Pair)
// 		})

// 		//-----------------------------------------------------------
// 		// PROTECTED ROUTES (JWT + SESSION VALIDATION REQUIRED)
// 		//-----------------------------------------------------------
// 		r.Group(func(r chi.Router) {
// 			// JWT Middleware (parses token and adds claims to context)
// 			r.Use(authMiddleware.JWTAuthMiddlewareWithRedis(sessionService, logger))
			
// 			// 🔥 NEW: Session Validation Middleware (performs all security checks)
// 			r.Use(authMiddleware.SessionValidationMiddleware(sessionService, logger))

// 			//-----------------------------------------------------------
// 			// USER AUTH PROTECTED ROUTES
// 			//-----------------------------------------------------------
// 			authHandler.RegisterProtectedRoutes(r)

// 			//-----------------------------------------------------------
// 			// COMPANY EMPLOYEE SEARCH ROUTES
// 			//-----------------------------------------------------------
// 			r.Route("/companies/{companyID}/employees", func(r chi.Router) {
// 				// Use EnhancedCompanyAccessMiddleware which checks JWT company ID
// 				r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))
				
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Post("/search", authHandler.SearchCompanyEmployees)
					
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/search/advanced", authHandler.SearchCompanyEmployeesAdvanced)
					
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/search/suggestions", authHandler.GetCompanyEmployeeSuggestions)
					
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/suggestions", authHandler.GetCompanyEmployeeSuggestions)
					
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/username/{username}", authHandler.FindCompanyEmployeeByUsername)
// 			})

// 			//-----------------------------------------------------------
// 			// COMPANY OWNER ROUTES (NON-ADMIN COMPANY OWNERS)
// 			//-----------------------------------------------------------
// 			r.Route("/companies/{companyID}", func(r chi.Router) {
// 				r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

// 				r.Get("/", adminHandler.GetCompany)
// 				r.Get("/getemployees", adminHandler.GetCompanyEmployees)
// 				r.Get("/departments", adminHandler.GetCompanyDepartments)
// 				r.Get("/roles", adminHandler.GetCompanyRoles)
// 				r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)
// 				r.Get("/stats", adminHandler.GetCompanyStats)

// 				// Owner-only operations
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.create", logger)).
// 					Post("/departments/create", rbacHandler.CreateDepartment)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// 					Put("/employees/{userID}/role", adminHandler.UpdateEmployeeRole)
// 			})

// 			//-----------------------------------------------------------
// 			// COMPANY RBAC ROUTES
// 			//-----------------------------------------------------------
// 			r.Route("/companies/{companyID}/rbac", func(r chi.Router) {
// 				r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

// 				// ===============================
// 				// ROLE MANAGEMENT
// 				// ===============================
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.create", logger)).
// 					Post("/roles", rbacHandler.CreateRole)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/roles", rbacHandler.ListRoles)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/roles/{roleID}", rbacHandler.GetRole)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
// 					Put("/roles/{roleID}", rbacHandler.UpdateRole)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.delete", logger)).
// 					Delete("/roles/{roleID}", rbacHandler.DeleteRole)

// 				// Employee Management
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
// 					Post("/employees", rbacHandler.AddEmployee)

// 				// Manager Management
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// 					Post("/managers", rbacHandler.AddManager)

// 				// Available Permissions
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
// 					Get("/available-permissions", rbacHandler.GetAvailablePermissions)

// 				// ===============================
// 				// PERMISSION MANAGEMENT
// 				// ===============================
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// 					Post("/roles/{roleID}/permissions", rbacHandler.AssignPermissionsToRole)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// 					Delete("/roles/{roleID}/permissions", rbacHandler.RemovePermissionsFromRole)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/roles/{roleID}/permissions", rbacHandler.GetRolePermissions)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// 					Put("/roles/{roleID}/permissions", rbacHandler.ReplaceRolePermissions)

// 				// ===============================
// 				// GLOBAL PERMISSION QUERIES
// 				// ===============================
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/permissions", rbacHandler.ListAllPermissions)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/permissions/module/{module}", rbacHandler.ListPermissionsByModule)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/permissions/name/{permissionName}", rbacHandler.GetPermissionByName)

// 				// ===============================
// 				// DEPARTMENT MANAGEMENT
// 				// ===============================
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/departments", rbacHandler.ListDepartments)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
// 					Put("/departments/{departmentID}", rbacHandler.UpdateDepartment)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
// 					Put("/departments/{departmentID}/rename", rbacHandler.RenameDepartment)

// 				// ===============================
// 				// USER PERMISSIONS & HIERARCHY
// 				// ===============================
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/users/{userID}/permissions", rbacHandler.GetUserPermissions)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/users/{userID}/permissions/bitmask", rbacHandler.GetUserPermissionBitmask)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/users/{userID}/permissions/check", rbacHandler.CheckUserPermission)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/users/{userID}/hierarchy", rbacHandler.GetUserHierarchy)

// 				// ===============================
// 				// BULK ROLE ASSIGNMENT
// 				// ===============================
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.role.assign", logger)).
// 					Post("/bulk-assign", rbacHandler.BulkAssignRoles)
// 			})

// 			//-----------------------------------------------------------
// 			// ADMIN PROTECTED ROUTES (WITH ADMIN SESSION CHECK)
// 			//-----------------------------------------------------------
// 			r.Route("/admin", func(r chi.Router) {
// 				// Admin session type check
// 				r.Use(AdminSessionMiddleware(logger))

// 				// 🔥 NEW BITMASK ADMIN ROUTES
// 				r.Route("/admins", func(r chi.Router) {
// 					// Admin stats
// 					r.Get("/stats", adminHandler.GetStats)
					
// 					// Phone management
// 					r.Patch("/phone", adminHandler.ChangeOwnPhone)  // Change own phone
// 					r.Patch("/{adminID}/phone", adminHandler.ChangeAdminPhone)  // Change other admin's phone
					
// 					// Admin invitation with bitmask
// 					r.Post("/invite", adminHandler.InviteAdminWithBitmask)
					
// 					// Admin promotion with bitmask
// 					r.Patch("/{adminID}/promote", adminHandler.PromoteAdminWithBitmask)
					
// 					// Get admins by role mask
// 					r.Get("/role/{roleMask}", adminHandler.GetAdminsByRoleMask)
					
// 					// Admin CRUD operations
// 					r.Get("/", adminHandler.ListAdmins)
// 					r.Get("/{adminID}", adminHandler.GetAdminByID)
// 					r.Get("/phone/{phone}", adminHandler.GetAdminByPhone)
// 					r.Delete("/{adminID}", adminHandler.RemoveAdmin)
// 					r.Patch("/{adminID}/deactivate", adminHandler.DeactivateAdmin)
// 					r.Patch("/{adminID}/activate", adminHandler.ActivateAdmin)
					
// 					// ===== PERMISSION MANAGEMENT =====
// 					r.Route("/{adminID}/permissions", func(r chi.Router) {
// 						// Get permissions
// 						r.Get("/", adminHandler.GetAdminPermissions)
// 						r.Get("/mask", adminHandler.GetAdminPermissionMask)
// 						r.Get("/check", adminHandler.CheckAdminPermission)
						
// 						// Permission operations
// 						r.Post("/{permissionName}", adminHandler.GrantPermissionToAdmin)
// 						r.Delete("/{permissionName}", adminHandler.RevokePermissionFromAdmin)
// 						r.Post("/batch", adminHandler.BatchUpdatePermissions)
// 					})
// 				})

// 				// System owner initialization (admin-only)
// 				r.Post("/init-owner", adminHandler.InitializeOwner)

// 				// Admin MPIN management
// 				r.Post("/mpin/change-by-admin", adminHandler.ChangeAdminMPINByAdmin)

// 				// User management
// 				r.Put("/users/update/{userID}", adminHandler.UpdateUser)
// 				r.Patch("/users/{userID}/kyc", adminHandler.UpdateUserKYC)
// 				r.Post("/users/{userID}/ban", adminHandler.BanUser)
// 				r.Post("/users/{userID}/unban", adminHandler.UnbanUser)
// 				r.Get("/users/banned", adminHandler.GetBannedUsers)

// 				// --------------------------------------------------------
// 				// SYSTEM / PERMISSIONS / COMPANY / EMPLOYEE / RBAC
// 				// --------------------------------------------------------
// 				r.Get("/debug/companies/{companyID}/departments", adminHandler.DebugCompanyDepartments)
// 				r.Route("/permissions", func(r chi.Router) {
// 					r.Get("/system-departments", adminHandler.GetSystemDepartments)
// 					r.Get("/", adminHandler.GetAllPermissions)
// 					r.Get("/module/{module}", adminHandler.GetPermissionsByModule)
// 				})

// 				// ADVANCED USER SEARCH ENDPOINTS (ADMIN ONLY)
// 				r.Route("/users", func(r chi.Router) {
// 					r.Get("/search", adminHandler.SearchUsers)
// 					r.Get("/search/advanced", adminHandler.SearchUsersAdvanced)
// 					r.Get("/search/suggestions", adminHandler.GetUserSuggestions)
// 					r.Get("/search/username", adminHandler.SearchUsersByUsername)
// 					r.Get("/search/fullname", adminHandler.SearchUsersByFullName)
// 					r.Get("/recently-active", adminHandler.GetRecentlyActiveUsers)
// 					r.Get("/kyc-status/{status}", adminHandler.ListUsersByKYCStatus)
// 				})

// 				// Company Management
// 				r.Route("/companies", func(r chi.Router) {
// 					r.Post("/", adminHandler.CreateCompany)
// 					r.Get("/status/{status}", adminHandler.GetCompaniesByStatus)
// 					r.Get("/recent", adminHandler.GetRecentCompanies)
// 					r.Get("/expiring-subscriptions", adminHandler.GetCompaniesWithExpiringSubscription)
// 					r.Get("/tier/{tier}", adminHandler.GetCompaniesByTier)

// 					r.Get("/search", adminHandler.SearchCompanies)
// 					r.Get("/suggestions", adminHandler.GetCompanySuggestions)
// 					r.Get("/search-by-owner/{ownerID}", adminHandler.SearchCompaniesByOwner)
// 					r.Get("/owner/{ownerID}/search", adminHandler.SearchCompaniesByOwner)
// 					r.Get("/search-analytics", adminHandler.GetCompanySearchAnalytics)
// 					r.Post("/search-benchmark", adminHandler.BenchmarkCompanySearch)

// 					r.Route("/{companyID}", func(r chi.Router) {
// 						r.Get("/", adminHandler.GetCompany)
// 						r.Patch("/deactivate", adminHandler.DeactivateCompany)
// 						r.Patch("/deactivate/department", rbacHandler.DeactivateDepartment)
// 						r.Delete("/delete", rbacHandler.DeleteDepartment)
// 						r.Patch("/activate", adminHandler.ReactivateCompany)
// 						r.Patch("/extend-subscription", adminHandler.ExtendSubscription)
// 						r.Patch("/subscription", adminHandler.UpdateSubscription)
// 						r.Get("/stats", adminHandler.GetCompanyStats)
// 						r.Get("/rbac-stats", adminHandler.GetCompanyRBACStats)

// 						r.Get("/employees", adminHandler.GetCompanyEmployees)
// 						r.Get("/departments", adminHandler.GetCompanyDepartments)
// 						r.Get("/roles", adminHandler.GetCompanyRoles)
// 						r.Post("/roles", adminHandler.CreateRole)
// 						r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)

// 						r.Post("/employees/bulk-assign", adminHandler.BulkAssignRoles)
// 					})
// 				})

// 				// Employee Management
// 				r.Route("/employees", func(r chi.Router) {
// 					r.Route("/{userID}", func(r chi.Router) {
// 						r.Put("/role", adminHandler.UpdateEmployeeRole)
// 						r.Get("/permissions", adminHandler.GetEmployeePermissions)
// 						r.Get("/hierarchy", adminHandler.GetUserHierarchy)
// 					})
// 					r.Post("/check-permission", adminHandler.CheckEmployeePermission)
// 				})

// 				// Role Permission Management
// 				r.Route("/roles", func(r chi.Router) {
// 					r.Route("/{roleID}", func(r chi.Router) {
// 						r.Post("/permissions", adminHandler.GrantRolePermissions)
// 					})
// 				})

// 				// ===== LEGACY COMPATIBILITY ROUTES (remove after migration) =====
// 				// Keep these temporarily if you need backward compatibility
// 				r.Get("/admins/role/{roleLevel}", adminHandler.GetAdminsByRole)  // Legacy string-based
// 				r.Get("/admins/status/{status}", adminHandler.GetAdminsByStatus)
				
// 				// Legacy admin management routes (redirect to new ones)
// 				r.Patch("/owner/phone", func(w http.ResponseWriter, r *http.Request) {
// 					// Redirect to new endpoint
// 					adminHandler.ChangeOwnPhone(w, r)
// 				})
// 				r.Post("/invite", func(w http.ResponseWriter, r *http.Request) {
// 					// Redirect to new bitmask endpoint
// 					adminHandler.InviteAdminWithBitmask(w, r)
// 				})
// 			})
// 		})
// 	})

// 	// ============================================================
// 	// GLOBAL ERROR HANDLERS
// 	// ============================================================
// 	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
// 		w.Header().Set("Content-Type", "application/json")
// 		w.WriteHeader(http.StatusNotFound)
// 		_ = json.NewEncoder(w).Encode(map[string]interface{}{
// 			"error":   "endpoint not found",
// 			"path":    r.URL.Path,
// 			"method":  r.Method,
// 			"service": "auth-service",
// 		})
// 	})

// 	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
// 		w.Header().Set("Content-Type", "application/json")
// 		w.WriteHeader(http.StatusMethodNotAllowed)
// 		_ = json.NewEncoder(w).Encode(map[string]interface{}{
// 			"error":   "method not allowed",
// 			"path":    r.URL.Path,
// 			"method":  r.Method,
// 			"service": "auth-service",
// 		})
// 	})

// 	return router
// }

// // ============================================================================
// // MIDDLEWARES
// // ============================================================================

// func AdminSessionMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			sessionType, ok := r.Context().Value("session_type").(string)
// 			if !ok || sessionType != "admin" {
// 				logger.Warn("Access denied: not an admin session",
// 					zap.String("session_type", sessionType),
// 					zap.String("path", r.URL.Path),
// 				)
// 				respondWithJWTError(w, logger, http.StatusForbidden, "Access denied: admin session required")
// 				return
// 			}
// 			next.ServeHTTP(w, r)
// 		})
// 	}
// }

// // Enhanced Company Access Middleware
// func EnhancedCompanyAccessMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			// Extract company ID from URL params
// 			companyIDStr := chi.URLParam(r, "companyID")
// 			companyID, err := uuid.Parse(companyIDStr)
// 			if err != nil {
// 				respondWithJWTError(w, logger, http.StatusBadRequest, "Invalid company ID")
// 				return
// 			}

// 			// Get session type from context
// 			sessionType, ok := r.Context().Value("session_type").(string)
// 			if !ok {
// 				respondWithJWTError(w, logger, http.StatusUnauthorized, "Session type not found")
// 				return
// 			}

// 			// Get user ID from context
// 			userIDStr, ok := r.Context().Value("user_id").(string)
// 			if !ok {
// 				respondWithJWTError(w, logger, http.StatusUnauthorized, "User not authenticated")
// 				return
// 			}

// 			userID, err := uuid.Parse(userIDStr)
// 			if err != nil {
// 				respondWithJWTError(w, logger, http.StatusBadRequest, "Invalid user ID")
// 				return
// 			}

// 			// For non-admin users, check company access
// 			if sessionType != "admin" {
// 				// Get company ID from context (validated by session validation middleware)
// 				validatedCompanyID, ok := r.Context().Value("validated_company_id").(string)
// 				if !ok || validatedCompanyID == "" {
// 					respondWithJWTError(w, logger, http.StatusForbidden, 
// 						"Company access denied: No validated company context")
// 					return
// 				}

// 				validatedCompanyUUID, err := uuid.Parse(validatedCompanyID)
// 				if err != nil {
// 					respondWithJWTError(w, logger, http.StatusForbidden, 
// 						"Company access denied: Invalid company ID in validated session")
// 					return
// 				}

// 				// Verify the user is accessing their own company
// 				if validatedCompanyUUID != companyID {
// 					logger.Warn("Company access violation",
// 						zap.String("user_id", userID.String()),
// 						zap.String("requested_company", companyID.String()),
// 						zap.String("validated_company", validatedCompanyID),
// 						zap.String("session_type", sessionType))
					
// 					respondWithJWTError(w, logger, http.StatusForbidden, 
// 						"Company access denied: You can only access your own company")
// 					return
// 				}

// 				logger.Debug("Company access verified for non-admin user",
// 					zap.String("user_id", userID.String()),
// 					zap.String("company_id", companyID.String()),
// 					zap.String("session_type", sessionType))
// 			} else {
// 				logger.Debug("Admin user accessing company - no company restriction",
// 					zap.String("admin_id", userID.String()),
// 					zap.String("company_id", companyID.String()))
// 			}

// 			// Add company ID and user ID to context
// 			ctx := context.WithValue(r.Context(), "company_id", companyID)
// 			ctx = context.WithValue(ctx, "current_user_id", userID)

// 			next.ServeHTTP(w, r.WithContext(ctx))
// 		})
// 	}
// }

// // Updated JWTAuthMiddlewareWithRedis to include bitmask handling
// func JWTAuthMiddlewareWithRedis(sessionService *service.SessionService, logger *zap.Logger) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			ctx := r.Context()

// 			authHeader := r.Header.Get("Authorization")
// 			if authHeader == "" {
// 				respondWithJWTError(w, logger, http.StatusUnauthorized, "Missing authorization header")
// 				return
// 			}

// 			parts := strings.Split(authHeader, " ")
// 			if len(parts) != 2 || parts[0] != "Bearer" {
// 				respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid authorization header format")
// 				return
// 			}

// 			accessToken := parts[1]
// 			claims, err := sessionService.ValidateAccessToken(ctx, accessToken)
// 			if err != nil {
// 				logger.Warn("Invalid JWT token", zap.Error(err))
// 				respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid or expired token")
// 				return
// 			}

// 			// Add claims to context
// 			ctx = context.WithValue(ctx, "user_id", claims.UserID)
// 			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
// 			ctx = context.WithValue(ctx, "role", claims.Role)
// 			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
// 			ctx = context.WithValue(ctx, "jti", claims.JTI)

// 			// Include permission mask and company ID in context
// 			if claims.PermissionMask != nil {
// 				ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)
// 			}
			
// 			if claims.CompanyID != "" {
// 				ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
// 			}

// 			// Include bitmask-specific claims
// 			if claims.AdminRoleMask != 0 {
// 				ctx = context.WithValue(ctx, "admin_role_mask", claims.AdminRoleMask)
// 			}

// 			next.ServeHTTP(w, r.WithContext(ctx))
// 		})
// 	}
// }

// func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			start := time.Now()
// 			ww := chiMiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
// 			next.ServeHTTP(ww, r)

// 			logger.Info("HTTP request",
// 				zap.String("method", r.Method),
// 				zap.String("path", r.URL.Path),
// 				zap.String("query", r.URL.RawQuery),
// 				zap.String("remote_addr", r.RemoteAddr),
// 				zap.Int("status", ww.Status()),
// 				zap.Duration("duration", time.Since(start)),
// 				zap.String("user_agent", r.UserAgent()),
// 			)
// 		})
// 	}
// }

// func requireHTTPS(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

// 		host := r.Host

// 		// Allow HTTP on local dev networks:
// 		if r.TLS == nil &&
// 			(strings.HasPrefix(host, "localhost") ||
// 				strings.HasPrefix(host, "127.0.0.1") ||
// 				strings.HasPrefix(host, "192.168.") ||
// 				strings.HasPrefix(host, "10.") ||
// 				strings.HasPrefix(host, "172.16.")) {

// 			next.ServeHTTP(w, r)
// 			return
// 		}

// 		// All other cases require HTTPS
// 		if r.TLS == nil {
// 			w.Header().Set("Content-Type", "application/json")
// 			w.WriteHeader(http.StatusUpgradeRequired)
// 			_ = json.NewEncoder(w).Encode(map[string]string{"error": "https required"})
// 			return
// 		}

// 		next.ServeHTTP(w, r)
// 	})
// }

// func respondWithJWTError(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string) {
// 	if logger != nil {
// 		logger.Warn("JWT auth error",
// 			zap.Int("status_code", statusCode),
// 			zap.String("message", message),
// 		)
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(statusCode)
// 	_ = json.NewEncoder(w).Encode(map[string]interface{}{
// 		"success": false,
// 		"error":   message,
// 		"message": "Authentication failed",
// 		"code":    statusCode,
// 	})
// }

// // Updated router.go with session validation
// package handler

// import (
// 	authMiddleware "auth-service/internal/middleware"
// 	"auth-service/internal/service"
// 	"context"
// 	"encoding/json"
// 	"net/http"
// 	"strings"
// 	"time"

// 	"github.com/go-chi/chi/v5"
// 	chiMiddleware "github.com/go-chi/chi/v5/middleware"
// 	"github.com/go-chi/cors"
// 	"github.com/google/uuid"
// 	"go.uber.org/zap"
// )

// func NewRouter(
// 	otpHandler *OTPHandler,
// 	adminHandler *AdminHandler,
// 	authHandler *AuthHandler,
// 	rbacHandler *RBACHandler,
// 	pairingHandler *PairingHandler,
// 	wsHandler *WebSocketHandler,
// 	sessionService *service.SessionService,
// 	jwtService *service.JWTService,
// 	logger *zap.Logger,
// ) chi.Router {
// 	router := chi.NewRouter()

// 	// ============================================================
// 	// GLOBAL MIDDLEWARES
// 	// ============================================================
// 	// router.Use(requireHTTPS)
// 	router.Use(chiMiddleware.RequestID)
// 	router.Use(chiMiddleware.RealIP)
// 	router.Use(LoggerMiddleware(logger))
// 	router.Use(chiMiddleware.Recoverer)
// 	router.Use(chiMiddleware.Timeout(60 * time.Second))

// 	// CORS - Add required headers
// 	router.Use(cors.Handler(cors.Options{
// 		AllowedOrigins:   []string{"https://*", "http://localhost:3000", "http://localhost:8080"},
// 		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
// 		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", 
// 			"X-Session-Type", "X-Device-ID", "X-Company-ID"}, // Added X-Company-ID
// 		AllowCredentials: true,
// 		MaxAge:           300,
// 	}))

// 	// ============================================================
// 	// HEALTH CHECK
// 	// ============================================================
// 	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
// 		logger.Info("Health check requested")
// 		w.Header().Set("Content-Type", "application/json")
// 		_ = json.NewEncoder(w).Encode(map[string]string{
// 			"status":  "healthy",
// 			"service": "auth-service",
// 			"time":    time.Now().UTC().Format(time.RFC3339),
// 		})
// 	})

// 	// ============================================================
// 	// MAIN API
// 	// ============================================================
// 	router.Route("/api/v1", func(r chi.Router) {

// 		//-----------------------------------------------------------
// 		// PUBLIC ROUTES
// 		//-----------------------------------------------------------
// 		authHandler.RegisterPublicRoutes(r)
// 		authHandler.RegisterUserPublicRoutes(r)
// 		otpHandler.RegisterRoutes(r)

// 		//-----------------------------------------------------------
// 		// WEB LOGIN (QR PAIRING) ROUTES
// 		//-----------------------------------------------------------
// 		r.Route("/web/login", func(r chi.Router) {
// 			r.Get("/qr", pairingHandler.GenerateQR)
// 			r.Get("/status", pairingHandler.Status)
// 			r.Post("/confirm", pairingHandler.Confirm)
// 			r.Get("/ws", pairingHandler.WebSocket)

// 			// Mobile pairing (requires JWT + Session Validation)
// 			r.With(
// 				authMiddleware.JWTAuthMiddleware(jwtService, logger),
// 				authMiddleware.SessionValidationMiddleware(sessionService, logger),
// 			).Post("/pair", pairingHandler.Pair)
// 		})

// 		//-----------------------------------------------------------
// 		// ADMIN AUTH (PUBLIC)
// 		//-----------------------------------------------------------
// 		adminHandler.RegisterRoutes(r)

// 		//-----------------------------------------------------------
// 		// PROTECTED ROUTES (JWT + SESSION VALIDATION REQUIRED)
// 		//-----------------------------------------------------------
// 		r.Group(func(r chi.Router) {
// 			// JWT Middleware (parses token and adds claims to context)
// 			r.Use(authMiddleware.JWTAuthMiddleware(jwtService, logger))
			
// 			// 🔥 NEW: Session Validation Middleware (performs all security checks)
// 			r.Use(authMiddleware.SessionValidationMiddleware(sessionService, logger))

// 			//-----------------------------------------------------------
// 			// USER AUTH PROTECTED ROUTES
// 			//-----------------------------------------------------------
// 			authHandler.RegisterProtectedRoutes(r)

// 			//-----------------------------------------------------------
// 			// COMPANY EMPLOYEE SEARCH ROUTES
// 			//-----------------------------------------------------------
// 			r.Route("/companies/{companyID}/employees", func(r chi.Router) {
// 				// Use EnhancedCompanyAccessMiddleware which checks JWT company ID
// 				r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))
				
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Post("/search", authHandler.SearchCompanyEmployees)
					
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/search/advanced", authHandler.SearchCompanyEmployeesAdvanced)
					
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/search/suggestions", authHandler.GetCompanyEmployeeSuggestions)
					
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/suggestions", authHandler.GetCompanyEmployeeSuggestions)
					
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/username/{username}", authHandler.FindCompanyEmployeeByUsername)
// 			})

// 			//-----------------------------------------------------------
// 			// COMPANY OWNER ROUTES (NON-ADMIN COMPANY OWNERS)
// 			//-----------------------------------------------------------
// 			r.Route("/companies/{companyID}", func(r chi.Router) {
// 				r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

// 				r.Get("/", adminHandler.GetCompany)
// 				r.Get("/getemployees", adminHandler.GetCompanyEmployees)
// 				r.Get("/departments", adminHandler.GetCompanyDepartments)
// 				r.Get("/roles", adminHandler.GetCompanyRoles)
// 				r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)
// 				r.Get("/stats", adminHandler.GetCompanyStats)

// 				// Owner-only operations
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.create", logger)).
// 					Post("/departments/create", rbacHandler.CreateDepartment)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// 					Put("/employees/{userID}/role", adminHandler.UpdateEmployeeRole)
// 			})

// 			//-----------------------------------------------------------
// 			// COMPANY RBAC ROUTES
// 			//-----------------------------------------------------------
// 			r.Route("/companies/{companyID}/rbac", func(r chi.Router) {
// 				r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

// 				// ===============================
// 				// ROLE MANAGEMENT
// 				// ===============================
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.create", logger)).
// 					Post("/roles", rbacHandler.CreateRole)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/roles", rbacHandler.ListRoles)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/roles/{roleID}", rbacHandler.GetRole)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
// 					Put("/roles/{roleID}", rbacHandler.UpdateRole)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.delete", logger)).
// 					Delete("/roles/{roleID}", rbacHandler.DeleteRole)

// 				// Employee Management
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
// 					Post("/employees", rbacHandler.AddEmployee)

// 				// Manager Management
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// 					Post("/managers", rbacHandler.AddManager)

// 				// Available Permissions
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
// 					Get("/available-permissions", rbacHandler.GetAvailablePermissions)

// 				// ===============================
// 				// PERMISSION MANAGEMENT
// 				// ===============================
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// 					Post("/roles/{roleID}/permissions", rbacHandler.AssignPermissionsToRole)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// 					Delete("/roles/{roleID}/permissions", rbacHandler.RemovePermissionsFromRole)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/roles/{roleID}/permissions", rbacHandler.GetRolePermissions)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// 					Put("/roles/{roleID}/permissions", rbacHandler.ReplaceRolePermissions)

// 				// ===============================
// 				// GLOBAL PERMISSION QUERIES
// 				// ===============================
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/permissions", rbacHandler.ListAllPermissions)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/permissions/module/{module}", rbacHandler.ListPermissionsByModule)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/permissions/name/{permissionName}", rbacHandler.GetPermissionByName)

// 				// ===============================
// 				// DEPARTMENT MANAGEMENT
// 				// ===============================
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// 					Get("/departments", rbacHandler.ListDepartments)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
// 					Put("/departments/{departmentID}", rbacHandler.UpdateDepartment)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
// 					Put("/departments/{departmentID}/rename", rbacHandler.RenameDepartment)


// 				// ===============================
// 				// USER PERMISSIONS & HIERARCHY
// 				// ===============================
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/users/{userID}/permissions", rbacHandler.GetUserPermissions)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/users/{userID}/permissions/bitmask", rbacHandler.GetUserPermissionBitmask)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/users/{userID}/permissions/check", rbacHandler.CheckUserPermission)

// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// 					Get("/users/{userID}/hierarchy", rbacHandler.GetUserHierarchy)

// 				// ===============================
// 				// BULK ROLE ASSIGNMENT
// 				// ===============================
// 				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.role.assign", logger)).
// 					Post("/bulk-assign", rbacHandler.BulkAssignRoles)
// 			})

// 			//-----------------------------------------------------------
// 			// ADMIN PROTECTED ROUTES (WITH ADMIN SESSION CHECK)
// 			//-----------------------------------------------------------
// 			r.Route("/admin", func(r chi.Router) {
// 				// Admin session type check
// 				r.Use(AdminSessionMiddleware(logger))

// 				// Admin routes
// 				r.Post("/mpin/change-by-admin", adminHandler.ChangeAdminMPINByAdmin)
// 				r.Put("/users/update/{userID}", adminHandler.UpdateUser)

// 				// --------------------------------------------------------
// 				// SYSTEM / PERMISSIONS / COMPANY / EMPLOYEE / RBAC
// 				// --------------------------------------------------------
// 				r.Get("/debug/companies/{companyID}/departments", adminHandler.DebugCompanyDepartments)
// 				r.Route("/permissions", func(r chi.Router) {
// 					r.Get("/system-departments", adminHandler.GetSystemDepartments)
// 					r.Get("/", adminHandler.GetAllPermissions)
// 					r.Get("/module/{module}", adminHandler.GetPermissionsByModule)
// 				})

// 				// ADVANCED USER SEARCH ENDPOINTS (ADMIN ONLY)
// 				r.Route("/users", func(r chi.Router) {
// 					r.Get("/search/advanced", adminHandler.SearchUsersAdvanced)
// 					r.Get("/search/suggestions", adminHandler.GetUserSuggestions)
// 					r.Get("/search/username", adminHandler.SearchUsersByUsername)
// 					r.Get("/search/fullname", adminHandler.SearchUsersByFullName)
// 					r.Get("/recently-active", adminHandler.GetRecentlyActiveUsers)
// 					r.Get("/kyc-status/{status}", adminHandler.ListUsersByKYCStatus)
					
// 					r.Patch("/{userID}/kyc", adminHandler.UpdateUserKYC)
// 					r.Post("/{userID}/ban", adminHandler.BanUser)
// 					r.Post("/{userID}/unban", adminHandler.UnbanUser)
// 					r.Get("/banned", adminHandler.GetBannedUsers)
// 				})

// 				// Company Management
// 				r.Route("/companies", func(r chi.Router) {
// 					r.Post("/", adminHandler.CreateCompany)
// 					r.Get("/status/{status}", adminHandler.GetCompaniesByStatus)
// 					r.Get("/recent", adminHandler.GetRecentCompanies)
// 					r.Get("/expiring-subscriptions", adminHandler.GetCompaniesWithExpiringSubscription)
// 					r.Get("/tier/{tier}", adminHandler.GetCompaniesByTier)

// 					r.Get("/search", adminHandler.SearchCompanies)
// 					r.Get("/suggestions", adminHandler.GetCompanySuggestions)
// 					r.Get("/search-by-owner/{ownerID}", adminHandler.SearchCompaniesByOwner)
// 					r.Get("/owner/{ownerID}/search", adminHandler.SearchCompaniesByOwner)
// 					r.Get("/search-analytics", adminHandler.GetCompanySearchAnalytics)
// 					r.Post("/search-benchmark", adminHandler.BenchmarkCompanySearch)

// 					r.Route("/{companyID}", func(r chi.Router) {
// 						r.Get("/", adminHandler.GetCompany)
// 						r.Patch("/deactivate", adminHandler.DeactivateCompany)
// 						r.Patch("/deactivate/department", rbacHandler.DeactivateDepartment) // Soft delete
// 						r.Delete("/delete", rbacHandler.DeleteDepartment)              // Hard delete
// 						r.Patch("/activate", adminHandler.ReactivateCompany)
// 						r.Patch("/extend-subscription", adminHandler.ExtendSubscription)
// 						r.Patch("/subscription", adminHandler.UpdateSubscription)
// 						r.Get("/stats", adminHandler.GetCompanyStats)
// 						r.Get("/rbac-stats", adminHandler.GetCompanyRBACStats)

// 						r.Get("/employees", adminHandler.GetCompanyEmployees)
// 						r.Get("/departments", adminHandler.GetCompanyDepartments)
// 						r.Get("/roles", adminHandler.GetCompanyRoles)
// 						r.Post("/roles", adminHandler.CreateRole)
// 						r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)

// 						r.Post("/employees/bulk-assign", adminHandler.BulkAssignRoles)
// 					})
// 				})

// 				// Employee Management
// 				r.Route("/employees", func(r chi.Router) {
// 					r.Route("/{userID}", func(r chi.Router) {
// 						r.Put("/role", adminHandler.UpdateEmployeeRole)
// 						r.Get("/permissions", adminHandler.GetEmployeePermissions)
// 						r.Get("/hierarchy", adminHandler.GetUserHierarchy)
// 					})
// 					r.Post("/check-permission", adminHandler.CheckEmployeePermission)
// 				})

// 				// Role Permission Management
// 				r.Route("/roles", func(r chi.Router) {
// 					r.Route("/{roleID}", func(r chi.Router) {
// 						r.Post("/permissions", adminHandler.GrantRolePermissions)
// 					})
// 				})

// 				// Admin Management
// 				r.Route("/admins", func(r chi.Router) {
// 					r.Get("/stats", adminHandler.GetStats)
// 					r.Patch("/owner/phone", adminHandler.ChangeOwnerPhone)
// 					r.Post("/invite", adminHandler.InviteAdmin)
// 					r.Patch("/{adminID}/promote", adminHandler.PromoteAdmin)
// 					r.Patch("/{adminID}/permissions", adminHandler.UpdateAdminPermissions)
// 					r.Delete("/{adminID}", adminHandler.RemoveAdmin)
// 					r.Patch("/{adminID}/deactivate", adminHandler.DeactivateAdmin)
// 					r.Patch("/{adminID}/activate", adminHandler.ActivateAdmin)
// 					r.Get("/{adminID}", adminHandler.GetAdminByID)
// 					r.Get("/phone/{phone}", adminHandler.GetAdminByPhone)
// 					r.Get("/", adminHandler.ListAdmins)
// 					r.Get("/role/{roleLevel}", adminHandler.GetAdminsByRole)
// 					r.Get("/status/{status}", adminHandler.GetAdminsByStatus)
// 				})

// 				// Alternative user management routes
// 				r.Route("/user-management", func(r chi.Router) {
// 					r.Patch("/{userID}/ban", adminHandler.BanUser)
// 					r.Patch("/{userID}/unban", adminHandler.UnbanUser)
// 					r.Get("/banned", adminHandler.GetBannedUsers)
// 					r.Patch("/{userID}/kyc", adminHandler.UpdateUserKYC)
// 				})
// 			})
// 		})
// 	})

// 	// ============================================================
// 	// GLOBAL ERROR HANDLERS
// 	// ============================================================
// 	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
// 		w.Header().Set("Content-Type", "application/json")
// 		w.WriteHeader(http.StatusNotFound)
// 		_ = json.NewEncoder(w).Encode(map[string]interface{}{
// 			"error":   "endpoint not found",
// 			"path":    r.URL.Path,
// 			"method":  r.Method,
// 			"service": "auth-service",
// 		})
// 	})

// 	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
// 		w.Header().Set("Content-Type", "application/json")
// 		w.WriteHeader(http.StatusMethodNotAllowed)
// 		_ = json.NewEncoder(w).Encode(map[string]interface{}{
// 			"error":   "method not allowed",
// 			"path":    r.URL.Path,
// 			"method":  r.Method,
// 			"service": "auth-service",
// 		})
// 	})

// 	return router
// }

// // ============================================================================
// // MIDDLEWARES
// // ============================================================================

// func AdminSessionMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			sessionType, ok := r.Context().Value("session_type").(string)
// 			if !ok || sessionType != "admin" {
// 				logger.Warn("Access denied: not an admin session",
// 					zap.String("session_type", sessionType),
// 					zap.String("path", r.URL.Path),
// 				)
// 				respondWithJWTError(w, logger, http.StatusForbidden, "Access denied: admin session required")
// 				return
// 			}
// 			next.ServeHTTP(w, r)
// 		})
// 	}
// }

// // Enhanced Company Access Middleware
// func EnhancedCompanyAccessMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			// Extract company ID from URL params
// 			companyIDStr := chi.URLParam(r, "companyID")
// 			companyID, err := uuid.Parse(companyIDStr)
// 			if err != nil {
// 				respondWithJWTError(w, logger, http.StatusBadRequest, "Invalid company ID")
// 				return
// 			}

// 			// Get session type from context
// 			sessionType, ok := r.Context().Value("session_type").(string)
// 			if !ok {
// 				respondWithJWTError(w, logger, http.StatusUnauthorized, "Session type not found")
// 				return
// 			}

// 			// Get user ID from context
// 			userIDStr, ok := r.Context().Value("user_id").(string)
// 			if !ok {
// 				respondWithJWTError(w, logger, http.StatusUnauthorized, "User not authenticated")
// 				return
// 			}

// 			userID, err := uuid.Parse(userIDStr)
// 			if err != nil {
// 				respondWithJWTError(w, logger, http.StatusBadRequest, "Invalid user ID")
// 				return
// 			}

// 			// For non-admin users, check company access
// 			if sessionType != "admin" {
// 				// Get company ID from context (validated by session validation middleware)
// 				validatedCompanyID, ok := r.Context().Value("validated_company_id").(string)
// 				if !ok || validatedCompanyID == "" {
// 					respondWithJWTError(w, logger, http.StatusForbidden, 
// 						"Company access denied: No validated company context")
// 					return
// 				}

// 				validatedCompanyUUID, err := uuid.Parse(validatedCompanyID)
// 				if err != nil {
// 					respondWithJWTError(w, logger, http.StatusForbidden, 
// 						"Company access denied: Invalid company ID in validated session")
// 					return
// 				}

// 				// Verify the user is accessing their own company
// 				if validatedCompanyUUID != companyID {
// 					logger.Warn("Company access violation",
// 						zap.String("user_id", userID.String()),
// 						zap.String("requested_company", companyID.String()),
// 						zap.String("validated_company", validatedCompanyID),
// 						zap.String("session_type", sessionType))
					
// 					respondWithJWTError(w, logger, http.StatusForbidden, 
// 						"Company access denied: You can only access your own company")
// 					return
// 				}

// 				logger.Debug("Company access verified for non-admin user",
// 					zap.String("user_id", userID.String()),
// 					zap.String("company_id", companyID.String()),
// 					zap.String("session_type", sessionType))
// 			} else {
// 				logger.Debug("Admin user accessing company - no company restriction",
// 					zap.String("admin_id", userID.String()),
// 					zap.String("company_id", companyID.String()))
// 			}

// 			// Add company ID and user ID to context
// 			ctx := context.WithValue(r.Context(), "company_id", companyID)
// 			ctx = context.WithValue(ctx, "current_user_id", userID)

// 			next.ServeHTTP(w, r.WithContext(ctx))
// 		})
// 	}
// }

// // // JWTAuthMiddleware - Updated to only parse JWT, not validate against Redis
// // func JWTAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
// // 	return func(next http.Handler) http.Handler {
// // 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// // 			ctx := r.Context()

// // 			authHeader := r.Header.Get("Authorization")
// // 			if authHeader == "" {
// // 				respondWithJWTError(w, logger, http.StatusUnauthorized, "Missing authorization header")
// // 				return
// // 			}

// // 			parts := strings.Split(authHeader, " ")
// // 			if len(parts) != 2 || parts[0] != "Bearer" {
// // 				respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid authorization header format")
// // 				return
// // 			}

// // 			accessToken := parts[1]
// // 			claims, err := jwtService.ValidateAccessToken(ctx, accessToken)
// // 			if err != nil {
// // 				logger.Warn("Invalid JWT token", zap.Error(err))
// // 				respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid or expired token")
// // 				return
// // 			}

// // 			// Add claims to context (SessionValidationMiddleware will validate against Redis)
// // 			ctx = context.WithValue(ctx, "user_id", claims.UserID)
// // 			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
// // 			ctx = context.WithValue(ctx, "role", claims.Role)
// // 			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
// // 			ctx = context.WithValue(ctx, "jti", claims.JTI)

// // 			// Include permission mask and company ID in context
// // 			if claims.PermissionMask != nil {
// // 				ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)
// // 			}
			
// // 			if claims.CompanyID != "" {
// // 				ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
// // 			}

// // 			if claims.AdminRoleLevel != "" {
// // 				ctx = context.WithValue(ctx, "admin_role_level", claims.AdminRoleLevel)
// // 			}
// // 			if claims.AdminPermissions != nil {
// // 				ctx = context.WithValue(ctx, "admin_permissions", claims.AdminPermissions)
// // 			}

// // 			next.ServeHTTP(w, r.WithContext(ctx))
// // 		})
// // 	}
// // }

// func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			start := time.Now()
// 			ww := chiMiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
// 			next.ServeHTTP(ww, r)

// 			logger.Info("HTTP request",
// 				zap.String("method", r.Method),
// 				zap.String("path", r.URL.Path),
// 				zap.String("query", r.URL.RawQuery),
// 				zap.String("remote_addr", r.RemoteAddr),
// 				zap.Int("status", ww.Status()),
// 				zap.Duration("duration", time.Since(start)),
// 				zap.String("user_agent", r.UserAgent()),
// 			)
// 		})
// 	}
// }

// func requireHTTPS(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

// 		host := r.Host

// 		// Allow HTTP on local dev networks:
// 		if r.TLS == nil &&
// 			(strings.HasPrefix(host, "localhost") ||
// 				strings.HasPrefix(host, "127.0.0.1") ||
// 				strings.HasPrefix(host, "192.168.") ||
// 				strings.HasPrefix(host, "10.") ||
// 				strings.HasPrefix(host, "172.16.")) {

// 			next.ServeHTTP(w, r)
// 			return
// 		}

// 		// All other cases require HTTPS
// 		if r.TLS == nil {
// 			w.Header().Set("Content-Type", "application/json")
// 			w.WriteHeader(http.StatusUpgradeRequired)
// 			_ = json.NewEncoder(w).Encode(map[string]string{"error": "https required"})
// 			return
// 		}

// 		next.ServeHTTP(w, r)
// 	})
// }

// func respondWithJWTError(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string) {
// 	if logger != nil {
// 		logger.Warn("JWT auth error",
// 			zap.Int("status_code", statusCode),
// 			zap.String("message", message),
// 		)
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(statusCode)
// 	_ = json.NewEncoder(w).Encode(map[string]interface{}{
// 		"success": false,
// 		"error":   message,
// 		"message": "Authentication failed",
// 		"code":    statusCode,
// 	})
// }

// package handler

// import (
//     authMiddleware "auth-service/internal/middleware"
//     "auth-service/internal/service"
//     "context"
//     "encoding/json"
//     "net/http"
//     "strings"
//     "time"

//     "github.com/go-chi/chi/v5"
//     chiMiddleware "github.com/go-chi/chi/v5/middleware"
//     "github.com/go-chi/cors"
//     "github.com/google/uuid"
//     "go.uber.org/zap"
// )

// func NewRouter(
//     otpHandler *OTPHandler,
//     adminHandler *AdminHandler,
//     authHandler *AuthHandler,
//     rbacHandler *RBACHandler,
//     pairingHandler *PairingHandler,
//     wsHandler *WebSocketHandler,
//     sessionService *service.SessionService,
//     jwtService *service.JWTService,
//     logger *zap.Logger,
// ) chi.Router {
//     router := chi.NewRouter()

//     // ============================================================
//     // GLOBAL MIDDLEWARES
//     // ============================================================
//     // router.Use(requireHTTPS)
//     router.Use(chiMiddleware.RequestID)
//     router.Use(chiMiddleware.RealIP)
//     router.Use(LoggerMiddleware(logger))
//     router.Use(chiMiddleware.Recoverer)
//     router.Use(chiMiddleware.Timeout(60 * time.Second))

//     // CORS
//     router.Use(cors.Handler(cors.Options{
//         AllowedOrigins:   []string{"https://*", "http://localhost:3000", "http://localhost:8080"},
//         AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
//         AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Session-Type", "X-Device-ID"},
//         AllowCredentials: true,
//         MaxAge:           300,
//     }))

//     // ============================================================
//     // HEALTH CHECK
//     // ============================================================
//     router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
//         logger.Info("Health check requested")
//         w.Header().Set("Content-Type", "application/json")
//         _ = json.NewEncoder(w).Encode(map[string]string{
//             "status":  "healthy",
//             "service": "auth-service",
//             "time":    time.Now().UTC().Format(time.RFC3339),
//         })
//     })

//     // ============================================================
//     // MAIN API
//     // ============================================================
//     router.Route("/api/v1", func(r chi.Router) {

//         //-----------------------------------------------------------
//         // PUBLIC ROUTES
//         //-----------------------------------------------------------
//         authHandler.RegisterPublicRoutes(r)
//         authHandler.RegisterUserPublicRoutes(r)
//         otpHandler.RegisterRoutes(r)

//         //-----------------------------------------------------------
//         // ✅ NEW: WEB LOGIN (QR PAIRING) ROUTES
//         //-----------------------------------------------------------
//         r.Route("/web/login", func(r chi.Router) {
//             r.Get("/qr", pairingHandler.GenerateQR)
//             r.Get("/status", pairingHandler.Status)
//             r.Post("/confirm", pairingHandler.Confirm)
//             r.Get("/ws", pairingHandler.WebSocket)

//             // Mobile pairing (requires JWT)
//             r.With(authMiddleware.JWTAuthMiddleware(jwtService, logger)).
//                 Post("/pair", pairingHandler.Pair)
//         })

//         //-----------------------------------------------------------
//         // ADMIN AUTH (PUBLIC) - Use RegisterRoutes for all admin auth endpoints
//         //-----------------------------------------------------------
//         adminHandler.RegisterRoutes(r)

//         //-----------------------------------------------------------
//         // PROTECTED ROUTES (JWT REQUIRED)
//         //-----------------------------------------------------------
//         r.Group(func(r chi.Router) {

//             // NEW JWT Middleware (injects permission mask + session type)
//             r.Use(authMiddleware.JWTAuthMiddleware(jwtService, logger))

//             //-----------------------------------------------------------
//             // USER AUTH PROTECTED ROUTES
//             //-----------------------------------------------------------
//             authHandler.RegisterProtectedRoutes(r)

//             // ✅ ADDED: COMPANY EMPLOYEE SEARCH ROUTES (for both admin and user)
//             //-----------------------------------------------------------
//             r.Route("/companies/{companyID}/employees", func(r chi.Router) {
//                 // ✅ Use EnhancedCompanyAccessMiddleware which checks JWT company ID for non-admin users
//                 r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))
                
//                 // Employee search endpoints (available to both admin and user with proper permissions)
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
//                     Post("/search", authHandler.SearchCompanyEmployees)
                    
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
//                     Get("/search/advanced", authHandler.SearchCompanyEmployeesAdvanced)
                    
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
//                     Get("/search/suggestions", authHandler.GetCompanyEmployeeSuggestions)
                    
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
//                     Get("/suggestions", authHandler.GetCompanyEmployeeSuggestions) // ✅ ADDED: Without /search prefix
                    
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
//                     Get("/username/{username}", authHandler.FindCompanyEmployeeByUsername)
//             })

//             //-----------------------------------------------------------
//             // COMPANY OWNER ROUTES (NON-ADMIN COMPANY OWNERS)
//             //-----------------------------------------------------------
//             r.Route("/companies/{companyID}", func(r chi.Router) {

//                 // ✅ Use EnhancedCompanyAccessMiddleware which checks JWT company ID for non-admin users
//                 r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

//                 r.Get("/", adminHandler.GetCompany)
//                 r.Get("/getemployees", adminHandler.GetCompanyEmployees)
//                 r.Get("/departments", adminHandler.GetCompanyDepartments)
//                 r.Get("/roles", adminHandler.GetCompanyRoles)
//                 r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)
//                 r.Get("/stats", adminHandler.GetCompanyStats)

//                 // Owner-only operations (protected by bitmask)
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.create", logger)).
//                     Post("/departments/create", rbacHandler.CreateDepartment)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
//                     Put("/employees/{userID}/role", adminHandler.UpdateEmployeeRole)
//             })

//             //-----------------------------------------------------------
//             // COMPANY RBAC ROUTES
//             //-----------------------------------------------------------
//             r.Route("/companies/{companyID}/rbac", func(r chi.Router) {

//                 // ✅ Use EnhancedCompanyAccessMiddleware which checks JWT company ID for non-admin users
//                 r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

//                 // ===============================
//                 // ROLE MANAGEMENT
//                 // ===============================
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.create", logger)).
//                     Post("/roles", rbacHandler.CreateRole)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
//                     Get("/roles", rbacHandler.ListRoles)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
//                     Get("/roles/{roleID}", rbacHandler.GetRole)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
//                     Put("/roles/{roleID}", rbacHandler.UpdateRole)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.delete", logger)).
//                     Delete("/roles/{roleID}", rbacHandler.DeleteRole)

//                 // Employee Management
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
//                     Post("/employees", rbacHandler.AddEmployee)

//                 // Manager Management
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
//                     Post("/managers", rbacHandler.AddManager)

//                 // Available Permissions for current user
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
//                     Get("/available-permissions", rbacHandler.GetAvailablePermissions)

//                 // ===============================
//                 // PERMISSION MANAGEMENT
//                 // ===============================
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
//                     Post("/roles/{roleID}/permissions", rbacHandler.AssignPermissionsToRole)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
//                     Delete("/roles/{roleID}/permissions", rbacHandler.RemovePermissionsFromRole)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
//                     Get("/roles/{roleID}/permissions", rbacHandler.GetRolePermissions)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
//                     Put("/roles/{roleID}/permissions", rbacHandler.ReplaceRolePermissions)

//                 // ===============================
//                 // GLOBAL PERMISSION QUERIES
//                 // ===============================
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
//                     Get("/permissions", rbacHandler.ListAllPermissions)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
//                     Get("/permissions/module/{module}", rbacHandler.ListPermissionsByModule)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
//                     Get("/permissions/name/{permissionName}", rbacHandler.GetPermissionByName)

//                 // ===============================
//                 // DEPARTMENT MANAGEMENT
//                 // ===============================

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
//                     Get("/departments", rbacHandler.ListDepartments)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
//                     Put("/departments/{departmentID}", rbacHandler.UpdateDepartment)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
//                     Put("/departments/{departmentID}/rename", rbacHandler.RenameDepartment)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.delete", logger)).
//                     Delete("/departments/{departmentID}", rbacHandler.DeactivateDepartment)

//                 // ===============================
//                 // USER PERMISSIONS & HIERARCHY
//                 // ===============================
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
//                     Get("/users/{userID}/permissions", rbacHandler.GetUserPermissions)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
//                     Get("/users/{userID}/permissions/bitmask", rbacHandler.GetUserPermissionBitmask)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
//                     Get("/users/{userID}/permissions/check", rbacHandler.CheckUserPermission)

//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
//                     Get("/users/{userID}/hierarchy", rbacHandler.GetUserHierarchy)

//                 // ===============================
//                 // BULK ROLE ASSIGNMENT
//                 // ===============================
//                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.role.assign", logger)).
//                     Post("/bulk-assign", rbacHandler.BulkAssignRoles)
//             })

//             //-----------------------------------------------------------
//             // ADMIN PROTECTED ROUTES
//             //-----------------------------------------------------------
//             r.Route("/admin", func(r chi.Router) {

//                 // NEW: Admin JWT middleware (admins automatically get full access)
//                 r.Use(authMiddleware.AdminJWTAuthMiddleware(jwtService, logger))
//                 r.Post("/mpin/change-by-admin", adminHandler.ChangeAdminMPINByAdmin)
//                 r.Put("/users/update/{userID}", adminHandler.UpdateUser)

//                 // All admin routes remain as they are
//                 // --------------------------------------------------------
//                 // SYSTEM / PERMISSIONS / COMPANY / EMPLOYEE / RBAC
//                 // --------------------------------------------------------
//                 r.Get("/debug/companies/{companyID}/departments", adminHandler.DebugCompanyDepartments)
//                 r.Route("/permissions", func(r chi.Router) {
//                     r.Get("/system-departments", adminHandler.GetSystemDepartments)
//                     r.Get("/", adminHandler.GetAllPermissions)
//                     r.Get("/module/{module}", adminHandler.GetPermissionsByModule)
//                 })

//                 // ✅ ADDED: ADVANCED USER SEARCH ENDPOINTS (ADMIN ONLY)
//                 //-----------------------------------------------------------
//                 r.Route("/users", func(r chi.Router) {
//                     r.Get("/search/advanced", adminHandler.SearchUsersAdvanced)          // Advanced user search with filters
//                     r.Get("/search/suggestions", adminHandler.GetUserSuggestions)        // User autocomplete suggestions
//                     r.Get("/search/username", adminHandler.SearchUsersByUsername)        // Search by username
//                     r.Get("/search/fullname", adminHandler.SearchUsersByFullName)        // Search by full name
//                     r.Get("/recently-active", adminHandler.GetRecentlyActiveUsers)       // Recently active users
//                     r.Get("/kyc-status/{status}", adminHandler.ListUsersByKYCStatus)     // Users by KYC status
                    
//                     // ✅ ADDED: MISSING USER MANAGEMENT ENDPOINTS
//                     r.Patch("/{userID}/kyc", adminHandler.UpdateUserKYC)                 // Update user KYC status
//                     r.Post("/{userID}/ban", adminHandler.BanUser)                        // Ban user
//                     r.Post("/{userID}/unban", adminHandler.UnbanUser)                    // Unban user
//                     r.Get("/banned", adminHandler.GetBannedUsers)                        // Get banned users
//                 })

//                 // Company Management
//                 r.Route("/companies", func(r chi.Router) {
//                     r.Post("/", adminHandler.CreateCompany)
//                     r.Get("/status/{status}", adminHandler.GetCompaniesByStatus)
//                     r.Get("/recent", adminHandler.GetRecentCompanies)
//                     r.Get("/expiring-subscriptions", adminHandler.GetCompaniesWithExpiringSubscription)
//                     r.Get("/tier/{tier}", adminHandler.GetCompaniesByTier)

//                     // ✅ ADDED: ADVANCED COMPANY SEARCH ENDPOINTS (ADMIN ONLY)
//                     r.Get("/search", adminHandler.SearchCompanies)                      // Full-text search with filters
//                     r.Get("/suggestions", adminHandler.GetCompanySuggestions)           // Autocomplete suggestions
//                     r.Get("/search-by-owner/{ownerID}", adminHandler.SearchCompaniesByOwner) // Search companies by owner
//                     r.Get("/owner/{ownerID}/search", adminHandler.SearchCompaniesByOwner) // ✅ ADDED: Alternative route for compatibility
//                     r.Get("/search-analytics", adminHandler.GetCompanySearchAnalytics)  // Search analytics
//                     r.Post("/search-benchmark", adminHandler.BenchmarkCompanySearch)    // Search benchmark

//                     r.Route("/{companyID}", func(r chi.Router) {
//                         r.Get("/", adminHandler.GetCompany)
//                         r.Patch("/deactivate", adminHandler.DeactivateCompany)
//                         r.Patch("/activate", adminHandler.ReactivateCompany)
//                         r.Patch("/extend-subscription", adminHandler.ExtendSubscription)
//                         r.Patch("/subscription", adminHandler.UpdateSubscription)
//                         r.Get("/stats", adminHandler.GetCompanyStats)
//                         r.Get("/rbac-stats", adminHandler.GetCompanyRBACStats)

//                         r.Get("/employees", adminHandler.GetCompanyEmployees)
//                         r.Get("/departments", adminHandler.GetCompanyDepartments)
//                         r.Get("/roles", adminHandler.GetCompanyRoles)
//                         r.Post("/roles", adminHandler.CreateRole)
//                         r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)

//                         r.Post("/employees/bulk-assign", adminHandler.BulkAssignRoles)
//                     })
//                 })

//                 // Employee Management
//                 r.Route("/employees", func(r chi.Router) {
//                     r.Route("/{userID}", func(r chi.Router) {
//                         r.Put("/role", adminHandler.UpdateEmployeeRole)
//                         r.Get("/permissions", adminHandler.GetEmployeePermissions)
//                         r.Get("/hierarchy", adminHandler.GetUserHierarchy)
//                     })
//                     r.Post("/check-permission", adminHandler.CheckEmployeePermission)
//                 })

//                 // Role Permission Management
//                 r.Route("/roles", func(r chi.Router) {
//                     r.Route("/{roleID}", func(r chi.Router) {
//                         r.Post("/permissions", adminHandler.GrantRolePermissions)
//                     })
//                 })

//                 // Admin Management
//                 r.Route("/admins", func(r chi.Router) {
//                     r.Get("/stats", adminHandler.GetStats)
//                     r.Patch("/owner/phone", adminHandler.ChangeOwnerPhone)
//                     r.Post("/invite", adminHandler.InviteAdmin)
//                     r.Patch("/{adminID}/promote", adminHandler.PromoteAdmin)
//                     r.Patch("/{adminID}/permissions", adminHandler.UpdateAdminPermissions)
//                     r.Delete("/{adminID}", adminHandler.RemoveAdmin)
//                     r.Patch("/{adminID}/deactivate", adminHandler.DeactivateAdmin)
//                     r.Patch("/{adminID}/activate", adminHandler.ActivateAdmin)
//                     r.Get("/{adminID}", adminHandler.GetAdminByID)
//                     r.Get("/phone/{phone}", adminHandler.GetAdminByPhone)
//                     r.Get("/", adminHandler.ListAdmins)
//                     r.Get("/role/{roleLevel}", adminHandler.GetAdminsByRole)
//                     r.Get("/status/{status}", adminHandler.GetAdminsByStatus)
//                 })

//                 // ✅ ADDED: Alternative user management routes for compatibility (some frontend calls use /admin/user-management)
//                 r.Route("/user-management", func(r chi.Router) {
//                     r.Patch("/{userID}/ban", adminHandler.BanUser)
//                     r.Patch("/{userID}/unban", adminHandler.UnbanUser)
//                     r.Get("/banned", adminHandler.GetBannedUsers)
//                     r.Patch("/{userID}/kyc", adminHandler.UpdateUserKYC)
//                 })
//             })
//         })
//     })

//     // ============================================================
//     // GLOBAL ERROR HANDLERS
//     // ============================================================
//     router.NotFound(func(w http.ResponseWriter, r *http.Request) {
//         w.Header().Set("Content-Type", "application/json")
//         w.WriteHeader(http.StatusNotFound)
//         _ = json.NewEncoder(w).Encode(map[string]interface{}{
//             "error":   "endpoint not found",
//             "path":    r.URL.Path,
//             "method":  r.Method,
//             "service": "auth-service",
//         })
//     })

//     router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
//         w.Header().Set("Content-Type", "application/json")
//         w.WriteHeader(http.StatusMethodNotAllowed)
//         _ = json.NewEncoder(w).Encode(map[string]interface{}{
//             "error":   "method not allowed",
//             "path":    r.URL.Path,
//             "method":  r.Method,
//             "service": "auth-service",
//         })
//     })

//     return router
// }

// // ============================================================================
// // MIDDLEWARES
// // ============================================================================

// func AdminSessionMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
//     return func(next http.Handler) http.Handler {
//         return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//             sessionType, ok := r.Context().Value("session_type").(string)
//             if !ok || sessionType != "admin" {
//                 logger.Warn("Access denied: not an admin session",
//                     zap.String("session_type", sessionType),
//                     zap.String("path", r.URL.Path),
//                 )
//                 respondWithJWTError(w, logger, http.StatusForbidden, "Access denied: admin session required")
//                 return
//             }
//             next.ServeHTTP(w, r)
//         })
//     }
// }

// // ✅ NEW: Enhanced Company Access Middleware
// // This middleware checks that non-admin users can only access companies they belong to
// func EnhancedCompanyAccessMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
//     return func(next http.Handler) http.Handler {
//         return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//             // Extract company ID from URL params
//             companyIDStr := chi.URLParam(r, "companyID")
//             companyID, err := uuid.Parse(companyIDStr)
//             if err != nil {
//                 respondWithJWTError(w, logger, http.StatusBadRequest, "Invalid company ID")
//                 return
//             }

//             // Get session type from context (set by JWTAuthMiddleware)
//             sessionType, ok := r.Context().Value("session_type").(string)
//             if !ok {
//                 respondWithJWTError(w, logger, http.StatusUnauthorized, "Session type not found")
//                 return
//             }

//             // Get user ID from context
//             userIDStr, ok := r.Context().Value("user_id").(string)
//             if !ok {
//                 respondWithJWTError(w, logger, http.StatusUnauthorized, "User not authenticated")
//                 return
//             }

//             userID, err := uuid.Parse(userIDStr)
//             if err != nil {
//                 respondWithJWTError(w, logger, http.StatusBadRequest, "Invalid user ID")
//                 return
//             }

//             // For non-admin users, check company access
//             if sessionType != "admin" {
//                 // Get company ID from JWT context
//                 jwtCompanyID, ok := r.Context().Value("company_id").(string)
//                 if !ok || jwtCompanyID == "" {
//                     respondWithJWTError(w, logger, http.StatusForbidden, 
//                         "Company access denied: No company context in token")
//                     return
//                 }

//                 jwtCompanyUUID, err := uuid.Parse(jwtCompanyID)
//                 if err != nil {
//                     respondWithJWTError(w, logger, http.StatusForbidden, 
//                         "Company access denied: Invalid company ID in token")
//                     return
//                 }

//                 // Verify the user is accessing their own company
//                 if jwtCompanyUUID != companyID {
//                     logger.Warn("Company access violation",
//                         zap.String("user_id", userID.String()),
//                         zap.String("requested_company", companyID.String()),
//                         zap.String("jwt_company", jwtCompanyID),
//                         zap.String("session_type", sessionType))
                    
//                     respondWithJWTError(w, logger, http.StatusForbidden, 
//                         "Company access denied: You can only access your own company")
//                     return
//                 }

//                 logger.Debug("Company access verified for non-admin user",
//                     zap.String("user_id", userID.String()),
//                     zap.String("company_id", companyID.String()),
//                     zap.String("session_type", sessionType))
//             } else {
//                 logger.Debug("Admin user accessing company - no company restriction",
//                     zap.String("admin_id", userID.String()),
//                     zap.String("company_id", companyID.String()))
//             }

//             // Add company ID and user ID to context
//             ctx := context.WithValue(r.Context(), "company_id", companyID)
//             ctx = context.WithValue(ctx, "current_user_id", userID)

//             next.ServeHTTP(w, r.WithContext(ctx))
//         })
//     }
// }

// // ✅ UPDATED: JWTAuthMiddleware to include company ID in context
// func JWTAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
//     return func(next http.Handler) http.Handler {
//         return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//             ctx := r.Context()

//             authHeader := r.Header.Get("Authorization")
//             if authHeader == "" {
//                 respondWithJWTError(w, logger, http.StatusUnauthorized, "Missing authorization header")
//                 return
//             }

//             parts := strings.Split(authHeader, " ")
//             if len(parts) != 2 || parts[0] != "Bearer" {
//                 respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid authorization header format")
//                 return
//             }

//             accessToken := parts[1]
//             claims, err := jwtService.ValidateAccessToken(ctx, accessToken)
//             if err != nil {
//                 logger.Warn("Invalid JWT token", zap.Error(err))
//                 respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid or expired token")
//                 return
//             }

//             // Add claims to context
//             ctx = context.WithValue(ctx, "user_id", claims.UserID)
//             ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
//             ctx = context.WithValue(ctx, "role", claims.Role)
//             ctx = context.WithValue(ctx, "session_type", claims.SessionType)
//             ctx = context.WithValue(ctx, "jti", claims.JTI)

//             // ✅ ADDED: Include permission mask and company ID in context
//             if claims.PermissionMask != nil {
//                 ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)
//             }
            
//             if claims.CompanyID != "" {
//                 ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
//             }

//             if claims.AdminRoleLevel != "" {
//                 ctx = context.WithValue(ctx, "admin_role_level", claims.AdminRoleLevel)
//             }
//             if claims.AdminPermissions != nil {
//                 ctx = context.WithValue(ctx, "admin_permissions", claims.AdminPermissions)
//             }

//             next.ServeHTTP(w, r.WithContext(ctx))
//         })
//     }
// }

// // ✅ NEW: Admin JWT Auth Middleware (for admin-only routes)
// func AdminJWTAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
//     return func(next http.Handler) http.Handler {
//         return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//             ctx := r.Context()

//             authHeader := r.Header.Get("Authorization")
//             if authHeader == "" {
//                 respondWithJWTError(w, logger, http.StatusUnauthorized, "Missing authorization header")
//                 return
//             }

//             parts := strings.Split(authHeader, " ")
//             if len(parts) != 2 || parts[0] != "Bearer" {
//                 respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid authorization header format")
//                 return
//             }

//             accessToken := parts[1]
//             claims, err := jwtService.ValidateAccessToken(ctx, accessToken)
//             if err != nil {
//                 logger.Warn("Invalid JWT token", zap.Error(err))
//                 respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid or expired token")
//                 return
//             }

//             // Verify admin session type
//             if claims.SessionType != "admin" {
//                 respondWithJWTError(w, logger, http.StatusForbidden, "Admin access required")
//                 return
//             }

//             // Add claims to context
//             ctx = context.WithValue(ctx, "user_id", claims.UserID)
//             ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
//             ctx = context.WithValue(ctx, "role", claims.Role)
//             ctx = context.WithValue(ctx, "session_type", claims.SessionType)
//             ctx = context.WithValue(ctx, "jti", claims.JTI)

//             if claims.AdminRoleLevel != "" {
//                 ctx = context.WithValue(ctx, "admin_role_level", claims.AdminRoleLevel)
//             }
//             if claims.AdminPermissions != nil {
//                 ctx = context.WithValue(ctx, "admin_permissions", claims.AdminPermissions)
//             }

//             next.ServeHTTP(w, r.WithContext(ctx))
//         })
//     }
// }

// func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
//     return func(next http.Handler) http.Handler {
//         return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//             start := time.Now()
//             ww := chiMiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
//             next.ServeHTTP(ww, r)

//             logger.Info("HTTP request",
//                 zap.String("method", r.Method),
//                 zap.String("path", r.URL.Path),
//                 zap.String("query", r.URL.RawQuery),
//                 zap.String("remote_addr", r.RemoteAddr),
//                 zap.Int("status", ww.Status()),
//                 zap.Duration("duration", time.Since(start)),
//                 zap.String("user_agent", r.UserAgent()),
//             )
//         })
//     }
// }

// func requireHTTPS(next http.Handler) http.Handler {
//     return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

//         host := r.Host

//         // Allow HTTP on local dev networks:
//         if r.TLS == nil &&
//             (strings.HasPrefix(host, "localhost") ||
//                 strings.HasPrefix(host, "127.0.0.1") ||
//                 strings.HasPrefix(host, "192.168.") ||
//                 strings.HasPrefix(host, "10.") ||
//                 strings.HasPrefix(host, "172.16.")) {

//             next.ServeHTTP(w, r)
//             return
//         }

//         // All other cases require HTTPS
//         if r.TLS == nil {
//             w.Header().Set("Content-Type", "application/json")
//             w.WriteHeader(http.StatusUpgradeRequired)
//             _ = json.NewEncoder(w).Encode(map[string]string{"error": "https required"})
//             return
//         }

//         next.ServeHTTP(w, r)
//     })
// }

// func respondWithJWTError(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string) {
//     if logger != nil {
//         logger.Warn("JWT auth error",
//             zap.Int("status_code", statusCode),
//             zap.String("message", message),
//         )
//     }

//     w.Header().Set("Content-Type", "application/json")
//     w.WriteHeader(statusCode)
//     _ = json.NewEncoder(w).Encode(map[string]interface{}{
//         "success": false,
//         "error":   message,
//         "message": "Authentication failed",
//         "code":    statusCode,
//     })
// }


// // package handler

// // import (
// //     authMiddleware "auth-service/internal/middleware"
// //     "auth-service/internal/service"
// //     "context"
// //     "encoding/json"
// //     "net/http"
// //     "strings"
// //     "time"

// //     "github.com/go-chi/chi/v5"
// //     chiMiddleware "github.com/go-chi/chi/v5/middleware"
// //     "github.com/go-chi/cors"
// //     "github.com/google/uuid"
// //     "go.uber.org/zap"
// // )

// // func NewRouter(
// //     otpHandler *OTPHandler,
// //     adminHandler *AdminHandler,
// //     authHandler *AuthHandler,
// //     rbacHandler *RBACHandler,
// //     pairingHandler *PairingHandler,
// //     wsHandler *WebSocketHandler,
// //     sessionService *service.SessionService,
// //     jwtService *service.JWTService,
// //     logger *zap.Logger,
// // ) chi.Router {
// //     router := chi.NewRouter()

// //     // ============================================================
// //     // GLOBAL MIDDLEWARES
// //     // ============================================================
// //     // router.Use(requireHTTPS)
// //     router.Use(chiMiddleware.RequestID)
// //     router.Use(chiMiddleware.RealIP)
// //     router.Use(LoggerMiddleware(logger))
// //     router.Use(chiMiddleware.Recoverer)
// //     router.Use(chiMiddleware.Timeout(60 * time.Second))

// //     // CORS
// //     router.Use(cors.Handler(cors.Options{
// //         AllowedOrigins:   []string{"https://*", "http://localhost:3000", "http://localhost:8080"},
// //         AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
// //         AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Session-Type", "X-Device-ID"},
// //         AllowCredentials: true,
// //         MaxAge:           300,
// //     }))

// //     // ============================================================
// //     // HEALTH CHECK
// //     // ============================================================
// //     router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
// //         logger.Info("Health check requested")
// //         w.Header().Set("Content-Type", "application/json")
// //         _ = json.NewEncoder(w).Encode(map[string]string{
// //             "status":  "healthy",
// //             "service": "auth-service",
// //             "time":    time.Now().UTC().Format(time.RFC3339),
// //         })
// //     })

// //     // ============================================================
// //     // MAIN API
// //     // ============================================================
// //     router.Route("/api/v1", func(r chi.Router) {

// //         //-----------------------------------------------------------
// //         // PUBLIC ROUTES
// //         //-----------------------------------------------------------
// //         authHandler.RegisterPublicRoutes(r)
// //         authHandler.RegisterUserPublicRoutes(r)
// //         otpHandler.RegisterRoutes(r)

// //         //-----------------------------------------------------------
// //         // ✅ NEW: WEB LOGIN (QR PAIRING) ROUTES
// //         //-----------------------------------------------------------
// //         r.Route("/web/login", func(r chi.Router) {
// //             r.Get("/qr", pairingHandler.GenerateQR)
// //             r.Get("/status", pairingHandler.Status)
// //             r.Post("/confirm", pairingHandler.Confirm)
// //             r.Get("/ws", pairingHandler.WebSocket)

// //             // Mobile pairing (requires JWT)
// //             r.With(authMiddleware.JWTAuthMiddleware(jwtService, logger)).
// //                 Post("/pair", pairingHandler.Pair)
// //         })

// //         //-----------------------------------------------------------
// //         // ADMIN AUTH (PUBLIC) - Use RegisterRoutes for all admin auth endpoints
// //         //-----------------------------------------------------------
// //         adminHandler.RegisterRoutes(r)

// //         //-----------------------------------------------------------
// //         // PROTECTED ROUTES (JWT REQUIRED)
// //         //-----------------------------------------------------------
// //         r.Group(func(r chi.Router) {

// //             // NEW JWT Middleware (injects permission mask + session type)
// //             r.Use(authMiddleware.JWTAuthMiddleware(jwtService, logger))

// //             //-----------------------------------------------------------
// //             // USER AUTH PROTECTED ROUTES
// //             //-----------------------------------------------------------
// //             authHandler.RegisterProtectedRoutes(r)

// //             // ✅ ADDED: COMPANY EMPLOYEE SEARCH ROUTES (for both admin and user)
// //             //-----------------------------------------------------------
// //             r.Route("/companies/{companyID}/employees", func(r chi.Router) {
// //                 r.Use(CompanyAccessMiddleware())
                
// //                 // Employee search endpoints (available to both admin and user with proper permissions)
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// //                     Post("/search", authHandler.SearchCompanyEmployees)
                    
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// //                     Get("/search/advanced", authHandler.SearchCompanyEmployeesAdvanced)
                    
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// //                     Get("/search/suggestions", authHandler.GetCompanyEmployeeSuggestions)
                    
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// //                     Get("/suggestions", authHandler.GetCompanyEmployeeSuggestions) // ✅ ADDED: Without /search prefix
                    
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// //                     Get("/username/{username}", authHandler.FindCompanyEmployeeByUsername)
// //             })

// //             //-----------------------------------------------------------
// //             // COMPANY OWNER ROUTES (NON-ADMIN COMPANY OWNERS)
// //             //-----------------------------------------------------------
// //             r.Route("/companies/{companyID}", func(r chi.Router) {

// //                 r.Use(CompanyAccessMiddleware())

// //                 r.Get("/", adminHandler.GetCompany)
// //                 r.Get("/getemployees", adminHandler.GetCompanyEmployees)
// //                 r.Get("/departments", adminHandler.GetCompanyDepartments)
// //                 r.Get("/roles", adminHandler.GetCompanyRoles)
// //                 r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)
// //                 r.Get("/stats", adminHandler.GetCompanyStats)

// //                 // Owner-only operations (protected by bitmask)
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.create", logger)).
// //                     Post("/departments/create", rbacHandler.CreateDepartment)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// //                     Put("/employees/{userID}/role", adminHandler.UpdateEmployeeRole)
// //             })

// //             //-----------------------------------------------------------
// //             // COMPANY RBAC ROUTES
// //             //-----------------------------------------------------------
// //             r.Route("/companies/{companyID}/rbac", func(r chi.Router) {

// //                 r.Use(CompanyAccessMiddleware())

// //                 // ===============================
// //                 // ROLE MANAGEMENT
// //                 // ===============================
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.create", logger)).
// //                     Post("/roles", rbacHandler.CreateRole)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// //                     Get("/roles", rbacHandler.ListRoles)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// //                     Get("/roles/{roleID}", rbacHandler.GetRole)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
// //                     Put("/roles/{roleID}", rbacHandler.UpdateRole)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.delete", logger)).
// //                     Delete("/roles/{roleID}", rbacHandler.DeleteRole)

// //                 // Employee Management
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
// //                     Post("/employees", rbacHandler.AddEmployee)

// //                 // Manager Management
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// //                     Post("/managers", rbacHandler.AddManager)

// //                 // Available Permissions for current user
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
// //                     Get("/available-permissions", rbacHandler.GetAvailablePermissions)

// //                 // ===============================
// //                 // PERMISSION MANAGEMENT
// //                 // ===============================
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// //                     Post("/roles/{roleID}/permissions", rbacHandler.AssignPermissionsToRole)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// //                     Delete("/roles/{roleID}/permissions", rbacHandler.RemovePermissionsFromRole)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// //                     Get("/roles/{roleID}/permissions", rbacHandler.GetRolePermissions)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
// //                     Put("/roles/{roleID}/permissions", rbacHandler.ReplaceRolePermissions)

// //                 // ===============================
// //                 // GLOBAL PERMISSION QUERIES
// //                 // ===============================
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// //                     Get("/permissions", rbacHandler.ListAllPermissions)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// //                     Get("/permissions/module/{module}", rbacHandler.ListPermissionsByModule)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// //                     Get("/permissions/name/{permissionName}", rbacHandler.GetPermissionByName)

// //                 // ===============================
// //                 // DEPARTMENT MANAGEMENT
// //                 // ===============================

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
// //                     Get("/departments", rbacHandler.ListDepartments)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
// //                     Put("/departments/{departmentID}", rbacHandler.UpdateDepartment)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
// //                     Put("/departments/{departmentID}/rename", rbacHandler.RenameDepartment)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.delete", logger)).
// //                     Delete("/departments/{departmentID}", rbacHandler.DeactivateDepartment)

// //                 // ===============================
// //                 // USER PERMISSIONS & HIERARCHY
// //                 // ===============================
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// //                     Get("/users/{userID}/permissions", rbacHandler.GetUserPermissions)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// //                     Get("/users/{userID}/permissions/bitmask", rbacHandler.GetUserPermissionBitmask)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// //                     Get("/users/{userID}/permissions/check", rbacHandler.CheckUserPermission)

// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
// //                     Get("/users/{userID}/hierarchy", rbacHandler.GetUserHierarchy)

// //                 // ===============================
// //                 // BULK ROLE ASSIGNMENT
// //                 // ===============================
// //                 r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.role.assign", logger)).
// //                     Post("/bulk-assign", rbacHandler.BulkAssignRoles)
// //             })

// //             //-----------------------------------------------------------
// //             // ADMIN PROTECTED ROUTES
// //             //-----------------------------------------------------------
// //             r.Route("/admin", func(r chi.Router) {

// //                 // NEW: Admin JWT middleware (admins automatically get full access)
// //                 r.Use(authMiddleware.AdminJWTAuthMiddleware(jwtService, logger))
// //                 r.Post("/mpin/change-by-admin", adminHandler.ChangeAdminMPINByAdmin)
// //                 r.Put("/users/update/{userID}", adminHandler.UpdateUser)

// //                 // All admin routes remain as they are
// //                 // --------------------------------------------------------
// //                 // SYSTEM / PERMISSIONS / COMPANY / EMPLOYEE / RBAC
// //                 // --------------------------------------------------------
// //                 r.Get("/debug/companies/{companyID}/departments", adminHandler.DebugCompanyDepartments)
// //                 r.Route("/permissions", func(r chi.Router) {
// //                     r.Get("/system-departments", adminHandler.GetSystemDepartments)
// //                     r.Get("/", adminHandler.GetAllPermissions)
// //                     r.Get("/module/{module}", adminHandler.GetPermissionsByModule)
// //                 })

// //                 // ✅ ADDED: ADVANCED USER SEARCH ENDPOINTS (ADMIN ONLY)
// //                 //-----------------------------------------------------------
// //                 r.Route("/users", func(r chi.Router) {
// //                     r.Get("/search/advanced", adminHandler.SearchUsersAdvanced)          // Advanced user search with filters
// //                     r.Get("/search/suggestions", adminHandler.GetUserSuggestions)        // User autocomplete suggestions
// //                     r.Get("/search/username", adminHandler.SearchUsersByUsername)        // Search by username
// //                     r.Get("/search/fullname", adminHandler.SearchUsersByFullName)        // Search by full name
// //                     r.Get("/recently-active", adminHandler.GetRecentlyActiveUsers)       // Recently active users
// //                     r.Get("/kyc-status/{status}", adminHandler.ListUsersByKYCStatus)     // Users by KYC status
                    
// //                     // ✅ ADDED: MISSING USER MANAGEMENT ENDPOINTS
// //                     r.Patch("/{userID}/kyc", adminHandler.UpdateUserKYC)                 // Update user KYC status
// //                     r.Post("/{userID}/ban", adminHandler.BanUser)                        // Ban user
// //                     r.Post("/{userID}/unban", adminHandler.UnbanUser)                    // Unban user
// //                     r.Get("/banned", adminHandler.GetBannedUsers)                        // Get banned users
// //                 })

// //                 // Company Management
// //                 r.Route("/companies", func(r chi.Router) {
// //                     r.Post("/", adminHandler.CreateCompany)
// //                     r.Get("/status/{status}", adminHandler.GetCompaniesByStatus)
// //                     r.Get("/recent", adminHandler.GetRecentCompanies)
// //                     r.Get("/expiring-subscriptions", adminHandler.GetCompaniesWithExpiringSubscription)
// //                     r.Get("/tier/{tier}", adminHandler.GetCompaniesByTier)

// //                     // ✅ ADDED: ADVANCED COMPANY SEARCH ENDPOINTS (ADMIN ONLY)
// //                     r.Get("/search", adminHandler.SearchCompanies)                      // Full-text search with filters
// //                     r.Get("/suggestions", adminHandler.GetCompanySuggestions)           // Autocomplete suggestions
// //                     r.Get("/search-by-owner/{ownerID}", adminHandler.SearchCompaniesByOwner) // Search companies by owner
// //                     r.Get("/owner/{ownerID}/search", adminHandler.SearchCompaniesByOwner) // ✅ ADDED: Alternative route for compatibility
// //                     r.Get("/search-analytics", adminHandler.GetCompanySearchAnalytics)  // Search analytics
// //                     r.Post("/search-benchmark", adminHandler.BenchmarkCompanySearch)    // Search benchmark

// //                     r.Route("/{companyID}", func(r chi.Router) {
// //                         r.Get("/", adminHandler.GetCompany)
// //                         r.Patch("/deactivate", adminHandler.DeactivateCompany)
// //                         r.Patch("/activate", adminHandler.ReactivateCompany)
// //                         r.Patch("/extend-subscription", adminHandler.ExtendSubscription)
// //                         r.Patch("/subscription", adminHandler.UpdateSubscription)
// //                         r.Get("/stats", adminHandler.GetCompanyStats)
// //                         r.Get("/rbac-stats", adminHandler.GetCompanyRBACStats)

// //                         r.Get("/employees", adminHandler.GetCompanyEmployees)
// //                         r.Get("/departments", adminHandler.GetCompanyDepartments)
// //                         r.Get("/roles", adminHandler.GetCompanyRoles)
// //                         r.Post("/roles", adminHandler.CreateRole)
// //                         r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)

// //                         r.Post("/employees/bulk-assign", adminHandler.BulkAssignRoles)
// //                     })
// //                 })

// //                 // Employee Management
// //                 r.Route("/employees", func(r chi.Router) {
// //                     r.Route("/{userID}", func(r chi.Router) {
// //                         r.Put("/role", adminHandler.UpdateEmployeeRole)
// //                         r.Get("/permissions", adminHandler.GetEmployeePermissions)
// //                         r.Get("/hierarchy", adminHandler.GetUserHierarchy)
// //                     })
// //                     r.Post("/check-permission", adminHandler.CheckEmployeePermission)
// //                 })

// //                 // Role Permission Management
// //                 r.Route("/roles", func(r chi.Router) {
// //                     r.Route("/{roleID}", func(r chi.Router) {
// //                         r.Post("/permissions", adminHandler.GrantRolePermissions)
// //                     })
// //                 })

// //                 // Admin Management
// //                 r.Route("/admins", func(r chi.Router) {
// //                     r.Get("/stats", adminHandler.GetStats)
// //                     r.Patch("/owner/phone", adminHandler.ChangeOwnerPhone)
// //                     r.Post("/invite", adminHandler.InviteAdmin)
// //                     r.Patch("/{adminID}/promote", adminHandler.PromoteAdmin)
// //                     r.Patch("/{adminID}/permissions", adminHandler.UpdateAdminPermissions)
// //                     r.Delete("/{adminID}", adminHandler.RemoveAdmin)
// //                     r.Patch("/{adminID}/deactivate", adminHandler.DeactivateAdmin)
// //                     r.Patch("/{adminID}/activate", adminHandler.ActivateAdmin)
// //                     r.Get("/{adminID}", adminHandler.GetAdminByID)
// //                     r.Get("/phone/{phone}", adminHandler.GetAdminByPhone)
// //                     r.Get("/", adminHandler.ListAdmins)
// //                     r.Get("/role/{roleLevel}", adminHandler.GetAdminsByRole)
// //                     r.Get("/status/{status}", adminHandler.GetAdminsByStatus)
// //                 })

// //                 // ✅ ADDED: Alternative user management routes for compatibility (some frontend calls use /admin/user-management)
// //                 r.Route("/user-management", func(r chi.Router) {
// //                     r.Patch("/{userID}/ban", adminHandler.BanUser)
// //                     r.Patch("/{userID}/unban", adminHandler.UnbanUser)
// //                     r.Get("/banned", adminHandler.GetBannedUsers)
// //                     r.Patch("/{userID}/kyc", adminHandler.UpdateUserKYC)
// //                 })
// //             })
// //         })
// //     })

// //     // ============================================================
// //     // GLOBAL ERROR HANDLERS
// //     // ============================================================
// //     router.NotFound(func(w http.ResponseWriter, r *http.Request) {
// //         w.Header().Set("Content-Type", "application/json")
// //         w.WriteHeader(http.StatusNotFound)
// //         _ = json.NewEncoder(w).Encode(map[string]interface{}{
// //             "error":   "endpoint not found",
// //             "path":    r.URL.Path,
// //             "method":  r.Method,
// //             "service": "auth-service",
// //         })
// //     })

// //     router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
// //         w.Header().Set("Content-Type", "application/json")
// //         w.WriteHeader(http.StatusMethodNotAllowed)
// //         _ = json.NewEncoder(w).Encode(map[string]interface{}{
// //             "error":   "method not allowed",
// //             "path":    r.URL.Path,
// //             "method":  r.Method,
// //             "service": "auth-service",
// //         })
// //     })

// //     return router
// // }

// // // ============================================================================
// // // MIDDLEWARES
// // // ============================================================================

// // func AdminSessionMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
// //     return func(next http.Handler) http.Handler {
// //         return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// //             sessionType, ok := r.Context().Value("session_type").(string)
// //             if !ok || sessionType != "admin" {
// //                 logger.Warn("Access denied: not an admin session",
// //                     zap.String("session_type", sessionType),
// //                     zap.String("path", r.URL.Path),
// //                 )
// //                 respondWithJWTError(w, logger, http.StatusForbidden, "Access denied: admin session required")
// //                 return
// //             }
// //             next.ServeHTTP(w, r)
// //         })
// //     }
// // }

// // func CompanyAccessMiddleware() func(http.Handler) http.Handler {
// //     return func(next http.Handler) http.Handler {
// //         return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// //             // Extract company ID from URL params
// //             companyIDStr := chi.URLParam(r, "companyID")
// //             companyID, err := uuid.Parse(companyIDStr)
// //             if err != nil {
// //                 respondWithJWTError(w, nil, http.StatusBadRequest, "Invalid company ID")
// //                 return
// //             }

// //             // Get user ID from context
// //             userIDStr, ok := r.Context().Value("user_id").(string)
// //             if !ok {
// //                 respondWithJWTError(w, nil, http.StatusUnauthorized, "User not authenticated")
// //                 return
// //             }

// //             userID, err := uuid.Parse(userIDStr)
// //             if err != nil {
// //                 respondWithJWTError(w, nil, http.StatusBadRequest, "Invalid user ID")
// //                 return
// //             }

// //             // Add company ID and user ID to context
// //             ctx := context.WithValue(r.Context(), "company_id", companyID)
// //             ctx = context.WithValue(ctx, "current_user_id", userID)

// //             next.ServeHTTP(w, r.WithContext(ctx))
// //         })
// //     }
// // }

// // func JWTAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
// //     return func(next http.Handler) http.Handler {
// //         return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// //             ctx := r.Context()

// //             authHeader := r.Header.Get("Authorization")
// //             if authHeader == "" {
// //                 respondWithJWTError(w, logger, http.StatusUnauthorized, "Missing authorization header")
// //                 return
// //             }

// //             parts := strings.Split(authHeader, " ")
// //             if len(parts) != 2 || parts[0] != "Bearer" {
// //                 respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid authorization header format")
// //                 return
// //             }

// //             accessToken := parts[1]
// //             claims, err := jwtService.ValidateAccessToken(ctx, accessToken)
// //             if err != nil {
// //                 logger.Warn("Invalid JWT token", zap.Error(err))
// //                 respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid or expired token")
// //                 return
// //             }

// //             // Add claims to context
// //             ctx = context.WithValue(ctx, "user_id", claims.UserID)
// //             ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
// //             ctx = context.WithValue(ctx, "role", claims.Role)
// //             ctx = context.WithValue(ctx, "session_type", claims.SessionType)
// //             ctx = context.WithValue(ctx, "jti", claims.JTI)

// //             if claims.AdminRoleLevel != "" {
// //                 ctx = context.WithValue(ctx, "admin_role_level", claims.AdminRoleLevel)
// //             }
// //             if claims.AdminPermissions != nil {
// //                 ctx = context.WithValue(ctx, "admin_permissions", claims.AdminPermissions)
// //             }

// //             next.ServeHTTP(w, r.WithContext(ctx))
// //         })
// //     }
// // }

// // func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
// //     return func(next http.Handler) http.Handler {
// //         return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// //             start := time.Now()
// //             ww := chiMiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
// //             next.ServeHTTP(ww, r)

// //             logger.Info("HTTP request",
// //                 zap.String("method", r.Method),
// //                 zap.String("path", r.URL.Path),
// //                 zap.String("query", r.URL.RawQuery),
// //                 zap.String("remote_addr", r.RemoteAddr),
// //                 zap.Int("status", ww.Status()),
// //                 zap.Duration("duration", time.Since(start)),
// //                 zap.String("user_agent", r.UserAgent()),
// //             )
// //         })
// //     }
// // }

// // func requireHTTPS(next http.Handler) http.Handler {
// //     return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

// //         host := r.Host

// //         // Allow HTTP on local dev networks:
// //         if r.TLS == nil &&
// //             (strings.HasPrefix(host, "localhost") ||
// //                 strings.HasPrefix(host, "127.0.0.1") ||
// //                 strings.HasPrefix(host, "192.168.") ||
// //                 strings.HasPrefix(host, "10.") ||
// //                 strings.HasPrefix(host, "172.16.")) {

// //             next.ServeHTTP(w, r)
// //             return
// //         }

// //         // All other cases require HTTPS
// //         if r.TLS == nil {
// //             w.Header().Set("Content-Type", "application/json")
// //             w.WriteHeader(http.StatusUpgradeRequired)
// //             _ = json.NewEncoder(w).Encode(map[string]string{"error": "https required"})
// //             return
// //         }

// //         next.ServeHTTP(w, r)
// //     })
// // }

// // func respondWithJWTError(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string) {
// //     if logger != nil {
// //         logger.Warn("JWT auth error",
// //             zap.Int("status_code", statusCode),
// //             zap.String("message", message),
// //         )
// //     }

// //     w.Header().Set("Content-Type", "application/json")
// //     w.WriteHeader(statusCode)
// //     _ = json.NewEncoder(w).Encode(map[string]interface{}{
// //         "success": false,
// //         "error":   message,
// //         "message": "Authentication failed",
// //         "code":    statusCode,
// //     })
// // }
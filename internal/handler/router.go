package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	academics "auth-service/internal/academics"
	academichandler "auth-service/internal/academics/handler"
	"auth-service/internal/accounting"
	"auth-service/internal/attendance"
	attendanceHandler "auth-service/internal/attendance/handler"
	attendanceMiddleware "auth-service/internal/attendance/middleware"
	"auth-service/internal/avatar"
	avatarHandler "auth-service/internal/avatar/handler"
	hrHandler "auth-service/internal/hr/handler"
	leavehandler "auth-service/internal/hr/leave/handler"
	middle "auth-service/internal/hr/middleware"
	payrollhandler "auth-service/internal/hr/payroll/handler"
	a "auth-service/internal/infrastructure/audit"
	"auth-service/internal/inventory"
	"auth-service/internal/kyc"
	"auth-service/internal/kyc/handler"
	authMiddleware "auth-service/internal/middleware"
	"auth-service/internal/sales"
	"auth-service/internal/service"
	"auth-service/internal/subscription"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
)

// AcademicHandlers groups all handlers required by academics.RegisterAcademicRoutes
type AcademicHandlers struct {
	AcademicYearHandler      *academichandler.AcademicYearHandler
	AdmissionHandler         *academichandler.AdmissionHandler
	AnalyticsHandler         *academichandler.AnalyticsHandler
	AssignmentHandler        *academichandler.AssignmentHandler
	CourseHandler            *academichandler.CourseHandler
	CurriculumHandler        *academichandler.CurriculumHandler
	EnrollmentHandler        *academichandler.EnrollmentHandler
	ExamHandler              *academichandler.ExamHandler
	FeeHandler               *academichandler.FeeHandler
	GradingHandler           *academichandler.GradingHandler
	GuardianHandler          *academichandler.GuardianHandler
	LibraryHandler           *academichandler.LibraryHandler
	NotificationHandler      *academichandler.NotificationHandler
	RoomHandler              *academichandler.RoomHandler
	SectionHandler           *academichandler.SectionHandler
	StudentHandler           *academichandler.StudentHandler
	SubjectHandler           *academichandler.SubjectHandler
	SubmissionHandler        *academichandler.SubmissionHandler
	TeacherHandler           *academichandler.TeacherHandler
	TermHandler              *academichandler.TermHandler
	TimetableHandler         *academichandler.TimetableHandler
	TransportHandler         *academichandler.TransportHandler
	SessionGenerationHandler *academichandler.SessionGenerationHandler
}

// NewRouter creates the main HTTP router with all application routes.
func NewRouter(
	otpHandler *OTPHandler,
	adminHandler *AdminHandler,
	authHandler *AuthHandler,
	rbacHandler *RBACHandler,
	auditHandler *a.AuditHandler,
	employeeHandler *hrHandler.EmployeeHandler,
	pairingHandler *PairingHandler,
	wsHandler *WebSocketHandler,
	sessionService *service.SessionService,
	jwtService *service.JWTService,
	orgUnitHandler *hrHandler.OrgUnitHandler,
	leaveAdminHandler *leavehandler.LeaveAdminHandler,
	leaveRequestHandler *leavehandler.LeaveRequestHandler,
	leaveQueryHandler *leavehandler.LeaveQueryHandler,
	payrollRunHandler *payrollhandler.PayrollRunHandler,
	leavePolicyResolutionHandler *leavehandler.LeavePolicyResolutionHandler,
	compHandler *payrollhandler.CompensationHandler,
	adjHandler *payrollhandler.PayrollAdjustmentHandler,
	cmdHandler *payrollhandler.PayrollCommandHandler,
	lockHandler *payrollhandler.PayrollLockHandler,
	queryHandler *payrollhandler.PayrollQueryHandler,
	runCmdHandler *payrollhandler.PayrollRunHandler,
	structHandler *payrollhandler.SalaryStructureHandler,
	statHandler *payrollhandler.StatutoryProfileHandler,
	attendanceRuleHandler *payrollhandler.AttendanceRuleHandler,
	employeeFineHandler *payrollhandler.EmployeeFineHandler,
	bankExportHandler *payrollhandler.BankExportHandler,
	componentHandler *payrollhandler.ComponentHandler,
	loanHandler *payrollhandler.LoanHandler,
	payslipHandler *payrollhandler.PayslipHandler,
	reportingHandler *payrollhandler.ReportingHandler,
	taxDeclarationHandler *payrollhandler.TaxDeclarationHandler,
	academicHandlers *AcademicHandlers,
	accountingHandlers *accounting.AccountingHandlers,
	inventoryHandlers *inventory.InventoryHandlers,
	salesHandlers *sales.SalesHandlers,
	subscriptionHandlers *subscription.SubscriptionHandlers,
	kycHandler *handler.KYCDocumentHandler,
	avatarHandler *avatarHandler.AvatarHandler,

	// Generic attendance handlers
	attendanceIngestHandler *attendanceHandler.AttendanceIngestHandler,
	attendanceQueryHandler *attendanceHandler.AttendanceQueryHandler,
	attendanceExemptionHandler *attendanceHandler.AttendanceExemptionHandler,
	attendanceResolutionHandler *attendanceHandler.AttendanceResolutionHandler,
	attendanceDeviceHandler *attendanceHandler.DeviceHandler,
	attendanceEnrollmentHandler *attendanceHandler.AttendanceDeviceEnrollmentHandler,
	attendanceTokenAdminHandler *attendanceHandler.DeviceTokenAdminHandler,
	attendanceSourceAdminHandler *attendanceHandler.AttendanceSourceAdminHandler,
	attendanceCorrectionHandler *attendanceHandler.AttendanceCorrectionHandler,
	attendanceReportHandler *attendanceHandler.AttendanceReportHandler,
	attendanceBatchHandler *attendanceHandler.BatchHandler,
	attendanceHeartbeatHandler *attendanceHandler.DeviceHeartbeatHandler,
	attendanceBiometricEnrollmentHandler *attendanceHandler.BiometricEnrollmentHandler,
	attendanceBiometricSyncHandler *attendanceHandler.BiometricSyncHandler,
	attendanceWorkCenterHandler *attendanceHandler.WorkCenterHandler,
	attendanceSchedulingHandler *attendanceHandler.SchedulingHandler,
	attendanceAdminHandler *attendanceHandler.AttendanceAdminHandler,
	sessionGenerationHandler *academichandler.SessionGenerationHandler,

	deviceAuthMiddleware *attendanceMiddleware.DeviceAuthMiddleware,
) chi.Router {
	router := chi.NewRouter()

	// ----- Global Middleware -----
	router.Use(chiMiddleware.RequestID)
	router.Use(chiMiddleware.RealIP)
	router.Use(chiMiddleware.Recoverer)
	router.Use(chiMiddleware.Timeout(60 * time.Second))

	router.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000",
			"http://localhost:8080",
			"https://*",
		},
		AllowedMethods: []string{
			"GET",
			"POST",
			"PUT",
			"PATCH",
			"DELETE",
			"OPTIONS",
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"Origin",
			"X-CSRF-Token",
			"X-Session-Type",
			"X-Device-ID",
			"X-Company-ID",
			"X-Device-Token",
			"ngrok-skip-browser-warning",
		},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"service": "auth-service",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})

	router.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", adminHandler.HealthCheckHandler)

		// Setup routes
		r.Route("/setup", func(r chi.Router) {
			r.Post("/super-admin", adminHandler.InitSuperAdminHandler)
			r.Get("/super-admin/status", adminHandler.CheckSuperAdminStatusHandler)
		})

		// ==========================================================
		// ADMIN AUTH ROUTES (now with idempotency middleware applied)
		// ==========================================================
		r.Route("/admin-auth", func(r chi.Router) {
			r.Use(IdempotencyMiddleware)

			r.Post("/login/initiate", adminHandler.InitiateAdminLogin)
			r.Post("/login/verify-otp", adminHandler.VerifyAdminOTPLogin)
			r.Post("/login/verify-mpin", adminHandler.VerifyAdminMPINLogin)
			r.Post("/mpin/setup", adminHandler.SetupAdminMPIN)
			r.Post("/mpin/change", adminHandler.ChangeAdminMPIN)
			r.Post("/mpin/forgot", adminHandler.ForgotAdminMPIN)
			r.Post("/mpin/forgot/verify", adminHandler.VerifyForgotAdminMPIN)
			r.Post("/refresh", adminHandler.RefreshAdminTokens)
			r.Post("/logout", adminHandler.LogoutAdmin)
			r.Get("/health", adminHandler.HealthCheck)
		})

		// Public auth routes
		authHandler.RegisterPublicRoutes(r)
		authHandler.RegisterUserPublicRoutes(r)
		otpHandler.RegisterRoutes(r)

		// Web login (QR pairing)
		r.Route("/web/login", func(r chi.Router) {
			r.Get("/qr", pairingHandler.GenerateQR)
			r.Get("/status", pairingHandler.Status)
			r.Post("/confirm", pairingHandler.Confirm)
			r.Get("/ws", pairingHandler.WebSocket)
			r.With(
				authMiddleware.JWTAuthMiddlewareWithRedis(sessionService),
				authMiddleware.SessionValidationMiddleware(sessionService),
			).Post("/pair", pairingHandler.Pair)
		})

		// ========== ATTENDANCE MODULE ROUTES ==========
		attendance.RegisterAttendanceRoutes(
			r,
			attendanceIngestHandler,
			attendanceQueryHandler,
			attendanceExemptionHandler,
			attendanceResolutionHandler,
			attendanceDeviceHandler,
			attendanceEnrollmentHandler,
			attendanceTokenAdminHandler,
			attendanceSourceAdminHandler,
			attendanceCorrectionHandler,
			attendanceReportHandler,
			attendanceBatchHandler,
			attendanceHeartbeatHandler,
			attendanceBiometricEnrollmentHandler,
			attendanceBiometricSyncHandler,
			attendanceWorkCenterHandler,
			attendanceSchedulingHandler,
			attendanceAdminHandler,
			authMiddleware.JWTAuthMiddlewareWithRedis(sessionService),
			authMiddleware.SessionValidationMiddleware(sessionService),
			authMiddleware.BitmaskPermissionMiddleware,
			deviceAuthMiddleware.Middleware,
			func(next http.Handler) http.Handler {
				return middle.CompanyAccessMiddlewareWithDeviceSupport(jwtService)(next)
			},
		)

		// Student login (public)
		r.Post("/companies/{companyID}/academics/students/login", academicHandlers.StudentHandler.Login)

		// 🆕 Public avatar file endpoint (signed URL, no auth required)
		r.Get("/avatars/file", avatarHandler.GetFile)

		// ========== PROTECTED ROUTES (JWT + session + idempotency) ==========
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.JWTAuthMiddlewareWithRedis(sessionService))
			r.Use(authMiddleware.SessionValidationMiddleware(sessionService))
			r.Use(IdempotencyMiddleware)

			authHandler.RegisterProtectedRoutes(r)

			// 🆕 Register avatar routes – they use administration permissions internally
			avatar.RegisterAvatarRoutes(r, avatarHandler)

			// ==========================================================
			// COMPANY‑SCOPED ADMINISTRATION ENDPOINTS
			// All GETs use administration.company.view, all writes use administration.company.update
			// ==========================================================

			// Employee search routes (company-scoped)
			r.Route("/companies/{companyID}/employees", func(r chi.Router) {
				r.Use(EnhancedCompanyAccessMiddleware(jwtService))
				// All reads require administration.company.view
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Post("/search", authHandler.SearchCompanyEmployees)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/search/advanced", authHandler.SearchCompanyEmployeesAdvanced)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/search/suggestions", authHandler.GetCompanyEmployeeSuggestions)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/suggestions", authHandler.GetCompanyEmployeeSuggestions)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/username/{username}", authHandler.FindCompanyEmployeeByUsername)
			})

			// Main company‑scoped routes
			r.Route("/companies/{companyID}", func(r chi.Router) {
				r.Use(EnhancedCompanyAccessMiddleware(jwtService))

				// ----- Company info (all require view) -----
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/", adminHandler.GetCompany)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/getemployees", adminHandler.GetCompanyEmployees)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/hierarchy", adminHandler.GetCompanyHierarchy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/stats", adminHandler.GetCompanyStats)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/users/{userID}/phone", authHandler.GetUserPhoneNumberInCompany)

				// ----- Departments (already administration.*, keep as is) -----
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/departments/search", adminHandler.SearchDepartments)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/departments/suggestions", adminHandler.GetDepartmentSuggestions)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/info", adminHandler.GetCompanyByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/deactivated-departments", adminHandler.GetDeactivatedDepartments)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/active-departments-count", adminHandler.GetActiveDepartmentCount)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/department-info", adminHandler.GetCompanyDepartmentInfo)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
					Get("/check-department-limit", adminHandler.CheckDepartmentLimit)

				// ----- Positions (replaced hr.position.* with administration.*) -----
				r.Route("/positions", func(r chi.Router) {
					// Reads
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/", adminHandler.ListPositions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/open", adminHandler.GetOpenPositions)
					// Writes
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Post("/", adminHandler.CreatePosition)
					r.Route("/{positionID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
							Get("/", adminHandler.GetPosition)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
							Put("/", adminHandler.UpdatePosition)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
							Delete("/", adminHandler.DeletePosition)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
							Patch("/status", adminHandler.UpdatePositionStatus)
					})
				})

				// ----- Departments (hierarchy) – already administration, keep -----
				r.Route("/departments", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/root", adminHandler.GetRootDepartments)

					r.Route("/{departmentID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
							Get("/children", adminHandler.GetDepartmentChildren)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
							Get("/tree", adminHandler.GetDepartmentTree)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
							Get("/parents", adminHandler.GetDepartmentParents)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
							Post("/validate-hierarchy", adminHandler.ValidateDepartmentHierarchy)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
							Put("/parent", adminHandler.UpdateDepartmentParent)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
							Post("/move", adminHandler.MoveDepartmentWithEmployees)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
							Delete("/soft", adminHandler.SoftDeleteDepartment)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
							Patch("/activate", adminHandler.ActivateDepartment)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
							Post("/sub-departments", adminHandler.CreateSubDepartment)
					})
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Post("/{parentDepartmentID}/sub-departments", adminHandler.CreateSubDepartment)
				})

				// ========== PAYROLL ROUTES (unchanged – they use payroll.* permissions) ==========
				r.Route("/payroll", func(r chi.Router) {
					// Bank details management
					r.Route("/bank-details", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/users/{userID}", bankExportHandler.CreateBankDetails)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/users/{userID}", bankExportHandler.ListUserBankDetails)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/users/{userID}/active", bankExportHandler.GetActiveBankDetails)
						r.Route("/{bankDetailID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Put("/", bankExportHandler.UpdateBankDetails)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Post("/activate", bankExportHandler.ActivateBankDetails)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Delete("/", bankExportHandler.DeactivateBankDetails)
						})
					})

					// Locks
					r.Route("/locks", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
							Get("/", lockHandler.ListLocks)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.update")).
							Post("/", lockHandler.CreateLock)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.update")).
							Delete("/", lockHandler.DeleteLock)
					})

					// Adjustments
					r.Route("/adjustments", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/", adjHandler.ListAdjustments)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/", adjHandler.CreateAdjustment)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/bulk", adjHandler.BulkCreateAdjustments)
						r.Route("/{adjustmentID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Get("/", adjHandler.GetAdjustment)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Put("/", adjHandler.UpdateAdjustment)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Delete("/", adjHandler.DeleteAdjustment)
						})
					})

					// Salary structures
					r.Route("/structures", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/", structHandler.ListStructures)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/", structHandler.CreateStructure)
						r.Route("/{structureID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Get("/", structHandler.GetStructure)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Put("/", structHandler.UpdateStructure)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Post("/clone", structHandler.CloneStructure)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Post("/publish", structHandler.PublishStructure)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Delete("/", structHandler.DeactivateStructure)
							r.Route("/components", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
									Post("/", structHandler.AddComponent)
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
									Post("/reorder", structHandler.ReorderComponents)
								r.Route("/{componentCode}", func(r chi.Router) {
									r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
										Put("/", structHandler.UpdateComponent)
									r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
										Delete("/", structHandler.RemoveComponent)
								})
							})
						})
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/assign", structHandler.AssignToEmployee)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/assign/bulk", structHandler.BulkAssignToEmployees)
					})

					// Statutory profiles
					r.Route("/statutory-profiles", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Get("/components", statHandler.ListComponentDefinitions)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Post("/components", statHandler.CreateComponentDefinition)
						r.Route("/components/{statutoryCode}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Put("/", statHandler.UpdateComponentDefinition)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Delete("/", statHandler.DeleteComponentDefinition)
						})
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Get("/rule-sets", statHandler.ListRuleSets)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Post("/rule-sets", statHandler.CreateRuleSet)
						r.Route("/rule-sets/{ruleSetID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Put("/", statHandler.UpdateRuleSet)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Delete("/", statHandler.DeactivateRuleSet)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Post("/activate", statHandler.ActivateRuleSet)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Post("/contributions", statHandler.CreateContributionRule)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Get("/contributions", statHandler.ListContributionRules)
							r.Route("/contributions/{ruleID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
									Put("/", statHandler.UpdateContributionRule)
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
									Delete("/", statHandler.DeleteContributionRule)
							})
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Post("/slabs", statHandler.CreateTaxSlab)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Get("/slabs", statHandler.ListTaxSlabs)
							r.Route("/slabs/{slabID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
									Put("/", statHandler.UpdateTaxSlab)
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
									Delete("/", statHandler.DeleteTaxSlab)
							})
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Post("/limits", statHandler.CreateDeductionLimit)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Get("/limits", statHandler.ListDeductionLimits)
							r.Route("/limits/{limitID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
									Put("/", statHandler.UpdateDeductionLimit)
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
									Delete("/", statHandler.DeleteDeductionLimit)
							})
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Post("/mappings", statHandler.CreateComponentMapping)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Post("/mappings/bulk", statHandler.BulkCreateComponentMappings)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Get("/mappings", statHandler.ListComponentMappings)
							r.Route("/mappings/{mappingID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
									Put("/", statHandler.UpdateComponentMapping)
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
									Delete("/", statHandler.DeleteComponentMapping)
							})
						})
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Get("/", statHandler.ListProfiles)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Post("/", statHandler.CreateProfile)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Post("/bulk", statHandler.BulkUpsertProfiles)
						r.Route("/{profileID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Put("/", statHandler.UpdateProfile)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
								Delete("/", statHandler.DeactivateProfile)
						})
					})

					// Attendance rules (payroll)
					r.Route("/attendance-rules", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/", attendanceRuleHandler.CreateRule)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/", attendanceRuleHandler.GetRules)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/active", attendanceRuleHandler.GetActiveRules)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/exists-active", attendanceRuleHandler.ExistsActiveRuleOfType)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/types/{ruleType}", attendanceRuleHandler.GetRulesByType)
						r.Route("/{ruleID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Get("/", attendanceRuleHandler.GetRuleByID)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Post("/versions", attendanceRuleHandler.UpdateRuleVersion)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Put("/activate", attendanceRuleHandler.ActivateRule)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Put("/deactivate", attendanceRuleHandler.DeactivateRule)
						})
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/bulk-deactivate-by-type", attendanceRuleHandler.BulkDeactivateByType)
					})

					// Employee fines
					r.Route("/fines", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/", employeeFineHandler.CreateFine)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/", employeeFineHandler.ListFines)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/summary", employeeFineHandler.GetCompanyFineSummary)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/bulk", employeeFineHandler.BulkCreateFines)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process")).
							Post("/lock-for-payroll-run", employeeFineHandler.LockFinesForPayrollRun)
						r.Route("/{fineID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Get("/", employeeFineHandler.GetFineByID)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Put("/", employeeFineHandler.UpdateFine)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Delete("/", employeeFineHandler.DeleteFine)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process")).
								Put("/process", employeeFineHandler.MarkFineAsProcessed)
						})
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Delete("/bulk/unprocessed", employeeFineHandler.BulkDeleteUnprocessed)
						r.Route("/employee/{userID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Get("/unprocessed", employeeFineHandler.GetEmployeeUnprocessedFines)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Get("/summary", employeeFineHandler.GetFineSummaryByEmployee)
						})
					})

					// Employee specific payroll endpoints
					r.Route("/employee/{userID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/salary", compHandler.GetEmployeeSalary)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/salary/snapshot", compHandler.GetSalarySnapshot)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/earnings/preview", compHandler.PreviewEarnings)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/adjustments", adjHandler.GetEmployeeAdjustmentsForPeriod)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Get("/statutory-profiles/active", statHandler.GetEmployeeActiveProfiles)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Get("/statutory-profiles/{code}/active", statHandler.GetActiveProfile)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Get("/statutory-profiles/{code}/history", statHandler.GetProfileHistory)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Post("/tax-regime", statHandler.ChangeTaxRegime)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
							Get("/history", queryHandler.GetEmployeePayrollHistory)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
							Get("/ytd", queryHandler.GetEmployeeYTD)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
							Get("/statutory-summary", queryHandler.GetEmployeeStatutorySummary)
					})

					// Payroll runs
					r.Route("/runs", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
							Get("/", queryHandler.ListRuns)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
							Get("/summary", queryHandler.GetRunSummary)
						r.Route("/{runID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
								Get("/", queryHandler.GetRunExecutionStatus)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
								Get("/ledger-summary", queryHandler.GetRunLedgerSummary)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
								Get("/execution-status", queryHandler.GetRunExecutionStatus)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
								Get("/employees", queryHandler.ListEmployeesInRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
								Get("/statutory-summary", queryHandler.GetRunStatutorySummary)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
								Get("/export", queryHandler.ExportRunToCSV)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process")).
								Post("/initialize", runCmdHandler.InitializeRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process")).
								Post("/execute", runCmdHandler.ExecuteRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.approve")).
								Post("/approve", runCmdHandler.ApproveRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process")).
								Post("/mark-paid", runCmdHandler.MarkRunAsPaid)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.update")).
								Post("/cancel", runCmdHandler.CancelRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process")).
								Post("/employees/{userID}/reprocess", cmdHandler.ReprocessEmployee)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
								Get("/bank-export", bankExportHandler.GenerateBankFile)
						})
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.create")).
							Post("/", runCmdHandler.CreateRun)
					})

					// Payroll components
					r.Route("/components", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/", componentHandler.ListComponents)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/default", componentHandler.GetDefaultComponent)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/clear-cache", componentHandler.ClearCache)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/{code}", componentHandler.GetComponent)
					})

					// Component management
					r.Route("/component-management", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/", payrollRunHandler.ListComponents)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/", payrollRunHandler.CreateComponent)
						r.Route("/{componentCode}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Put("/", payrollRunHandler.UpdateComponent)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
								Delete("/", payrollRunHandler.DeactivateComponent)
						})
					})

					// Loans
					r.Route("/loans", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/", loanHandler.CreateLoan)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/preview-emi", loanHandler.PreviewEMI)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/user/{userId}", loanHandler.ListUserLoans)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/{loanID}", loanHandler.GetLoan)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/{loanID}/pending-emis", loanHandler.GetPendingEMIsForLoan)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/{loanID}/close", loanHandler.CloseLoan)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/{loanID}/manual-payment", loanHandler.RecordManualPayment)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Get("/{loanID}/payments", loanHandler.ListLoanPayments)
					})

					// EMIs under payroll runs
					r.Route("/runs/{payrollRunID}/pending-emis", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
							Get("/", loanHandler.GetPendingEMIsForPayrollRun)
					})
					r.Route("/emis/{emiID}/paid", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage")).
							Post("/", loanHandler.MarkEMIAsPaid)
					})

					// Payslips
					r.Route("/payslips", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process")).
							Post("/runs/{runId}/generate", payslipHandler.GeneratePayslipsForRun)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
							Get("/runs/{runId}/users/{userId}/download", payslipHandler.DownloadPayslip)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process")).
							Post("/runs/{runId}/users/{userId}/send-email", payslipHandler.SendPayslipEmail)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
							Get("/users/{userId}", payslipHandler.ListUserPayslips)
					})

					// Reports
					r.Route("/reports", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.report.view")).
							Post("/statutory-challan", reportingHandler.GenerateStatutoryChallan)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.report.view")).
							Post("/payroll-register", reportingHandler.GeneratePayrollRegister)
					})

					// Tax declarations
					r.Route("/tax-declarations", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Post("/types", taxDeclarationHandler.CreateDeclarationType)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Put("/types/{typeCode}", taxDeclarationHandler.UpdateDeclarationType)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.view")).
							Get("/types", taxDeclarationHandler.ListDeclarationTypes)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.view")).
							Get("/types/{typeCode}", taxDeclarationHandler.GetDeclarationType)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Post("/declarations", taxDeclarationHandler.CreateDeclaration)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Put("/declarations/{declarationID}", taxDeclarationHandler.UpdateDeclaration)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage")).
							Post("/declarations/{declarationID}/verify", taxDeclarationHandler.VerifyDeclaration)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.view")).
							Get("/declarations/user/{userID}", taxDeclarationHandler.ListDeclarationsByUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.view")).
							Get("/declarations", taxDeclarationHandler.ListDeclarationsByFinancialYear)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.view")).
							Get("/declarations/total", taxDeclarationHandler.GetTotalDeclaredAmount)
					})

					// Trends and existing payslip endpoints
					r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
						Get("/trend", queryHandler.GetCompanyPayrollTrend)
					r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.view")).
						Get("/components/{componentCode}/trend", queryHandler.GetComponentBreakdownTrend)
					r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view")).
						Get("/payslip/{payrollItemID}", queryHandler.GetEmployeePayslip)
				})

				// ========== LEAVE ROUTES (unchanged) ==========
				r.Route("/leave", func(r chi.Router) {
					r.Route("/admin", func(r chi.Router) {
						r.Route("/policy-config", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
								Post("/", leaveAdminHandler.CreateLeavePolicy)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
								Get("/", leaveAdminHandler.ListActiveLeavePolicies)
							r.Route("/{policyID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
									Get("/", leaveAdminHandler.GetLeavePolicy)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
									Patch("/", leaveAdminHandler.UpdateLeavePolicy)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
									Delete("/", leaveAdminHandler.DeactivateLeavePolicy)
								r.Route("/rules", func(r chi.Router) {
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
										Post("/", leaveAdminHandler.AddPolicyRule)
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
										Get("/", leaveAdminHandler.GetPolicyRules)
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
										Patch("/{policyRuleID}", leaveAdminHandler.UpdatePolicyRule)
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
										Delete("/{policyRuleID}", leaveAdminHandler.DeletePolicyRule)
								})
							})
						})
						r.Route("/leave-types", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
								Get("/", leaveAdminHandler.ListLeaveTypes)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create")).
								Post("/", leaveAdminHandler.CreateLeaveType)
							r.Route("/{leaveTypeID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
									Get("/", leaveAdminHandler.GetLeaveType)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
									Put("/", leaveAdminHandler.UpdateLeaveType)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.delete")).
									Delete("/", leaveAdminHandler.DeleteLeaveType)
							})
						})
						r.Route("/entitlements", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
								Post("/", leaveAdminHandler.CreateEntitlement)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
								Get("/", leavePolicyResolutionHandler.ListEntitlements)
						})
						r.Route("/accruals", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
								Post("/monthly", leaveAdminHandler.ProcessMonthlyAccruals)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
								Get("/", leaveAdminHandler.GetAccrualsByDate)
						})
						r.Route("/recalculate", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
								Post("/{entitlementID}", leaveAdminHandler.RecalculateEntitlement)
						})
						r.Route("/policies", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
								Post("/resolve/user/{userID}", leavePolicyResolutionHandler.ResolveSingleUser)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
								Post("/resolve/batch", leavePolicyResolutionHandler.ResolveBatchUsers)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
								Get("/effective/{userID}", leavePolicyResolutionHandler.GetEffectivePolicies)
						})
					})
					r.Route("/requests", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.request")).
							Post("/", leaveRequestHandler.RequestLeave)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view")).
							Get("/", leaveRequestHandler.ListLeaveRequests)
						r.Route("/{requestID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view")).
								Get("/", leaveRequestHandler.GetLeaveRequest)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.approve")).
								Post("/approve", leaveRequestHandler.ApproveLeave)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.reject")).
								Post("/reject", leaveRequestHandler.RejectLeave)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.request")).
								Post("/cancel", leaveRequestHandler.CancelLeave)
						})
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.approve")).
							Get("/pending", leaveRequestHandler.GetPendingRequests)
					})
					r.Route("/query", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view")).
							Get("/balance", leaveQueryHandler.GetLeaveBalance)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view")).
							Get("/balance/{leaveTypeID}", leaveQueryHandler.GetLeaveBalanceByType)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view")).
							Get("/users/{userID}/balance", leaveQueryHandler.GetLeaveBalanceForUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view")).
							Get("/users/{userID}/balance/{leaveTypeID}", leaveQueryHandler.GetLeaveBalanceForUserByType)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view")).
							Get("/status", leaveQueryHandler.IsUserOnLeave)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view")).
							Get("/users/{userID}/history", leaveQueryHandler.GetUserLeaveHistory)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view")).
							Get("/users/{userID}/transactions", leaveQueryHandler.GetLeaveTransactionHistory)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view")).
							Get("/forecast", leaveQueryHandler.GetLeaveForecast)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view")).
							Get("/availability", leaveQueryHandler.CheckLeaveAvailability)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view")).
							Post("/availability", leaveQueryHandler.CheckLeaveAvailability)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
							Get("/report/utilization", leaveQueryHandler.GetLeaveUtilizationReport)
					})
				})

				// ========== HR ROUTES (unchanged – they use hr.employee.*) ==========
				r.Route("/hr", func(r chi.Router) {
					r.Route("/employees", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
							Get("/", employeeHandler.ListEmployeeProfiles)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create")).
							Post("/", employeeHandler.CreateEmployeeProfile)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.search")).
							Get("/search", employeeHandler.SearchEmployeeProfiles)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
							Get("/stats", employeeHandler.GetEmployeeStats)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
							Get("/export", employeeHandler.ExportEmployeeData)
						r.Route("/{employeeID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
								Get("/", employeeHandler.GetEmployeeProfile)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
								Put("/", employeeHandler.UpdateEmployeeProfile)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.delete")).
								Delete("/", employeeHandler.DeleteEmployeeProfile)
							r.Route("/documents", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.view")).
									Get("/", employeeHandler.GetEmployeeDocuments)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.upload")).
									Post("/", employeeHandler.UploadEmployeeDocument)
								r.Route("/{documentID}", func(r chi.Router) {
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.view")).
										Get("/", employeeHandler.DownloadEmployeeDocument)
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.view")).
										Get("/url", employeeHandler.GenerateDocumentURL)
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.delete")).
										Delete("/", employeeHandler.DeleteEmployeeDocument)
								})
							})
							r.Route("/department-history", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
									Get("/", employeeHandler.GetDepartmentHistory)
							})
							r.Route("/exit", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
									Get("/", employeeHandler.GetEmployeeExit)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.terminate")).
									Post("/", employeeHandler.CreateEmployeeExit)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.terminate")).
									Post("/rehire", employeeHandler.RehireEmployee)
							})
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
								Get("/role-history", employeeHandler.GetRoleHistory)
						})
						r.Route("/user/{userID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
								Get("/profile", employeeHandler.GetEmployeeProfileByUserID)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.view")).
								Get("/documents", employeeHandler.GetEmployeeDocuments)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.upload")).
								Post("/documents", employeeHandler.UploadEmployeeDocument)
						})
					})
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/permissions/module/{module}", rbacHandler.ListPermissionsByModule)

					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
						Get("/health", employeeHandler.HealthCheck)
				})

				// ========== ORG UNITS (unchanged – they use hr.employee.*) ==========
				r.Route("/org-units", func(r chi.Router) {
					r.Use(EnhancedCompanyAccessMiddleware(jwtService))
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
						Get("/", orgUnitHandler.ListOrgUnits)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
						Get("/search", orgUnitHandler.SearchOrgUnits)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
						Get("/active", orgUnitHandler.GetActiveOrgUnits)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create")).
						Post("/", orgUnitHandler.CreateOrgUnit)
					r.With(authMiddleware.BitmaskPermissionMiddleware("it.system.config.view")).
						Get("/health", orgUnitHandler.HealthCheck)
					r.Route("/{orgUnitID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
							Get("/", orgUnitHandler.GetOrgUnit)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
							Put("/", orgUnitHandler.UpdateOrgUnit)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.delete")).
							Delete("/", orgUnitHandler.DeleteOrgUnit)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
							Post("/members", orgUnitHandler.AddMember)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
							Get("/members", orgUnitHandler.GetOrgUnitMembers)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
							Post("/roles", orgUnitHandler.AssignRole)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
							Get("/roles", orgUnitHandler.GetOrgUnitRoles)
						r.Route("/members/{userID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
								Put("/", orgUnitHandler.UpdateMember)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
								Delete("/", orgUnitHandler.RemoveMember)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
								Delete("/roles/{role}", orgUnitHandler.RemoveRole)
						})
					})
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view")).
						Get("/user/{userID}/memberships", orgUnitHandler.GetUserMemberships)
				})

				// ========== RBAC ROUTES (administration.* for all company‑scoped RBAC) ==========
				r.Route("/rbac", func(r chi.Router) {
					// Roles – already administration
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Post("/roles", rbacHandler.CreateRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/roles", rbacHandler.ListRoles)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/roles/{roleID}", rbacHandler.GetRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Put("/roles/{roleID}", rbacHandler.UpdateRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Delete("/roles/{roleID}", rbacHandler.DeleteRole)

					// Employees and managers – now administration.company.update for writes
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Post("/employees", rbacHandler.AddEmployee)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Patch("/employees/{userID}", rbacHandler.UpdateEmployee)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Post("/managers", rbacHandler.AddManager)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Put("/employees/{userID}/position", rbacHandler.UpdateEmployeePosition)

					// View employee details – administration.company.view
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/employees/{userID}", rbacHandler.GetEmployeeWithPosition)

					// Permissions & other RBAC reads – administration.company.view
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/available-permissions", rbacHandler.GetAvailablePermissions)

					// Write permissions
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Post("/roles/{roleID}/permissions", rbacHandler.AssignPermissionsToRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Delete("/roles/{roleID}/permissions", rbacHandler.RemovePermissionsFromRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/roles/{roleID}/permissions", rbacHandler.GetRolePermissions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/roles/{roleID}/departments", rbacHandler.GetRoleDepartmentsForPermission)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Put("/roles/{roleID}/permissions", rbacHandler.ReplaceRolePermissions)

					// Permission listing – administration.company.view
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/permissions", rbacHandler.ListAllPermissions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/permissions/module/{module}", rbacHandler.ListPermissionsByModule)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/permissions/name/{permissionName}", rbacHandler.GetPermissionByName)

					// Departments – administration.company.view and update
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/departments", rbacHandler.ListDepartments)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Put("/departments/{departmentID}/rename", rbacHandler.RenameDepartment)

					// User permissions – administration.company.view (used in admin UI)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/users/{userID}/permissions", rbacHandler.GetUserPermissions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/users/{userID}/permissions/bitmask", rbacHandler.GetUserPermissionBitmask)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/users/{userID}/permissions/check", rbacHandler.CheckUserPermission)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
						Get("/users/{userID}/hierarchy", rbacHandler.GetUserHierarchy)

					// Bulk assign – administration.company.update
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
						Post("/bulk-assign", rbacHandler.BulkAssignRoles)
				})

				// ========== ACADEMIC ROUTES (unchanged – they use academics.*) ==========
				academics.RegisterAcademicRoutes(
					r,
					academicHandlers.AcademicYearHandler,
					academicHandlers.AdmissionHandler,
					academicHandlers.AnalyticsHandler,
					academicHandlers.AssignmentHandler,
					academicHandlers.CourseHandler,
					academicHandlers.CurriculumHandler,
					academicHandlers.EnrollmentHandler,
					academicHandlers.ExamHandler,
					academicHandlers.FeeHandler,
					academicHandlers.GradingHandler,
					academicHandlers.GuardianHandler,
					academicHandlers.LibraryHandler,
					academicHandlers.NotificationHandler,
					academicHandlers.RoomHandler,
					academicHandlers.SectionHandler,
					academicHandlers.StudentHandler,
					academicHandlers.SubjectHandler,
					academicHandlers.SubmissionHandler,
					academicHandlers.TeacherHandler,
					academicHandlers.TermHandler,
					academicHandlers.TimetableHandler,
					academicHandlers.TransportHandler,
					academicHandlers.SessionGenerationHandler,
				)
				accounting.RegisterAccountingRoutes(r, accountingHandlers, jwtService)
				inventory.RegisterInventoryRoutes(r, inventoryHandlers, jwtService)

			}) // end /companies/{companyID}

			// ========== SALES ROUTES (unchanged) ==========
			sales.RegisterSalesRoutes(r, salesHandlers, jwtService)

			// ========== SUBSCRIPTION ROUTES (unchanged) ==========
			subscription.RegisterSubscriptionRoutes(r, subscriptionHandlers)

			// Internal leave resolution (unchanged)
			r.Route("/internal/leave", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
					Post("/resolve/onboarding", leavePolicyResolutionHandler.ResolveOnboarding)
				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update")).
					Post("/resolve/position-change", leavePolicyResolutionHandler.ResolvePositionChange)
			})

			// ========== ADMIN ROUTES (system‑wide, unchanged) ==========
			r.Route("/admin", func(r chi.Router) {
				r.Use(AdminSessionMiddleware)
				// Admin admins
				r.Route("/admins", func(r chi.Router) {
					r.Get("/stats", adminHandler.GetStats)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.create")).
						Post("/", adminHandler.CreateAdminUser)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.system_config")).
						Get("/{adminID}/phone", adminHandler.GetAdminPhoneNumber)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/", adminHandler.ListAdmins)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/all", adminHandler.GetAllAdmins)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/active", adminHandler.GetActiveAdmins)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/inactive", adminHandler.GetInactiveAdmins)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/role-type/{roleType}", adminHandler.GetAdminsByRoleType)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/role/{roleID}", adminHandler.GetAdminsByRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/available-managers", adminHandler.GetAvailableManagers)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/search", adminHandler.SearchAdmins)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/search/advanced", adminHandler.SearchAdminsAdvanced)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/search/name", adminHandler.SearchAdminsByName)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/search/employees", adminHandler.SearchAdminEmployees)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.manager.view")).
						Get("/search/managers", adminHandler.SearchAdminManagers)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/search/suggestions", adminHandler.GetAdminSuggestions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/search/analytics", adminHandler.GetAdminSearchAnalytics)
					r.Route("/{adminID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
							Get("/", adminHandler.GetAdminUser)
						r.Get("/departments", adminHandler.GetAdminDepartments)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Put("/", adminHandler.UpdateAdminUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.delete")).
							Delete("/", adminHandler.DeleteAdminUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
							Put("/role", adminHandler.UpdateAdminUserRole)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Put("/profile", adminHandler.UpdateAdminProfile)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Put("/phone", adminHandler.ChangeAdminPhone)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Put("/reports-to", adminHandler.UpdateAdminReportsTo)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Post("/activate", adminHandler.ActivateAdmin)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Post("/deactivate", adminHandler.DeactivateAdmin)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Post("/avatar", adminHandler.SetAdminAvatar)
						r.Get("/avatar", adminHandler.GetAdminAvatar)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Delete("/avatar", adminHandler.DeactivateAdminAvatar)
						r.Get("/avatar/with-fallback", adminHandler.GetAdminAvatarWithFallback)
						r.Get("/avatar/info", adminHandler.GetAvatarInfo)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
							Get("/direct-reports", adminHandler.GetDirectReports)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
							Get("/reporting-chain", adminHandler.GetReportingChain)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
							Get("/hierarchy", adminHandler.GetAdminHierarchy)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
							Get("/permissions", adminHandler.GetAdminPermissions)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
							Get("/permissions/mask", adminHandler.GetAdminPermissionMask)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
							Get("/permissions/check", adminHandler.CheckAdminPermission)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
							Get("/with-permissions", adminHandler.GetAdminWithPermissions)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
							Get("/details", adminHandler.GetAdminWithDetails)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
							Get("/with-reports-to-name", adminHandler.GetAdminWithReportsToName)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
							Get("/department-access/{department}", adminHandler.CheckAdminDepartmentAccess)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Post("/reset-failed-login", adminHandler.ResetAdminFailedLoginAttempts)
					})
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
						Post("/bulk-update-reports-to", adminHandler.BulkUpdateReportsTo)
				})

				// ========== ADMIN ROLES (system‑wide) ==========
				r.Route("/roles", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
						Post("/employee", adminHandler.CreateEmployeeRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
						Get("/employee", adminHandler.GetEmployeeAdminRoles)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
						Post("/manager", adminHandler.CreateManagerRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
						Get("/manager", adminHandler.GetManagerAdminRoles)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
						Post("/", adminHandler.CreateAdminRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
						Get("/", adminHandler.GetAdminRoles)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
						Get("/search", adminHandler.SearchAdminRoles)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
						Get("/type/{roleType}", adminHandler.GetAdminRolesByType)
					r.Route("/{roleID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
							Get("/", adminHandler.GetAdminRole)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
							Get("/details", adminHandler.GetAdminRoleWithDetails)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
							Put("/", adminHandler.UpdateAdminRole)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
							Delete("/", adminHandler.DeleteAdminRole)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
							Get("/departments", adminHandler.GetAdminRoleDepartments)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
							Post("/departments/{departmentID}", adminHandler.AssignDepartmentToAdminRole)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
							Delete("/departments/{departmentID}", adminHandler.RemoveDepartmentFromAdminRole)
					})
				})

				// System departments (super‑admin only)
				r.Route("/departments", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_departments")).
						Get("/", adminHandler.GetSystemDepartments)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
						Get("/{departmentID}/admins", adminHandler.GetAdminsByDepartment)
				})

				// Admin MPIN management by super‑admin
				r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles")).
					Post("/mpin/change-by-admin", adminHandler.ChangeAdminMPINByAdmin)

				// User management (system‑wide)
				r.Route("/user-management", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/search/advanced", adminHandler.SearchUsersAdvanced)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/search/username", adminHandler.SearchUsersByUsername)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/search/full-name", adminHandler.SearchUsersByFullName)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/suggestions", adminHandler.GetUserSuggestions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/kyc/{status}", adminHandler.ListUsersByKYCStatus)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/recently-active", adminHandler.GetRecentlyActiveUsers)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
						Get("/banned", adminHandler.GetBannedUsers)
					r.Route("/{userID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Put("/", adminHandler.UpdateUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Patch("/kyc", adminHandler.UpdateUserKYC)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Post("/ban", adminHandler.BanUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
							Post("/unban", adminHandler.UnbanUser)
					})
				})

				// Company management (system‑wide)
				r.Route("/companies", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.create")).
						Post("/", adminHandler.CreateCompany)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
						Get("/", adminHandler.GetRecentCompanies)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
						Get("/search", adminHandler.SearchCompanies)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
						Get("/suggestions", adminHandler.GetCompanySuggestions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
						Get("/analytics/search", adminHandler.GetCompanySearchAnalytics)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update")).
						Post("/search/benchmark", adminHandler.BenchmarkCompanySearch)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
						Get("/status/{status}", adminHandler.GetCompaniesByStatus)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
						Get("/tier/{tier}", adminHandler.GetCompaniesByTier)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
						Get("/expiring", adminHandler.GetCompaniesWithExpiringSubscription)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
						Get("/owner/{ownerID}/search", adminHandler.SearchCompaniesByOwner)
					r.Route("/{companyID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
							Get("/", adminHandler.GetCompany)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
							Get("/stats", adminHandler.GetCompanyStats)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
							Get("/employees", adminHandler.GetCompanyEmployees)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
							Get("/departments", adminHandler.GetCompanyDepartments)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
							Get("/hierarchy", adminHandler.GetCompanyHierarchy)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
							Get("/rbac-stats", adminHandler.GetCompanyRBACStats)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view")).
							Get("/roles", adminHandler.GetCompanyRoles)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_departments")).
							Post("/", adminHandler.AdminAddDepartment)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update")).
							Put("/max-departments", adminHandler.UpdateMaxDepartments)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update")).
							Put("/subscription", adminHandler.UpdateSubscription)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update")).
							Post("/subscription/extend", adminHandler.ExtendSubscription)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.suspend")).
							Post("/deactivate", adminHandler.DeactivateCompany)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update")).
							Post("/reactivate", adminHandler.ReactivateCompany)
					})
				})

				// System configuration & permissions
				r.Route("/system", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_departments")).
						Get("/departments", adminHandler.GetSystemDepartments)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_permissions")).
						Get("/permissions", adminHandler.GetAllPermissions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_permissions")).
						Get("/permissions/module/{module}", adminHandler.GetPermissionsByModule)
				})

				// Bulk avatar info (view permission)
				r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
					Post("/bulk-avatar-info", adminHandler.BulkGetAvatarInfo)

				// Audit logs (super‑admin only)
				r.Route("/audit", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.audit_logs")).
						Get("/logs", auditHandler.GetSystemAuditLogs)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.audit_logs")).
						Get("/export", auditHandler.ExportSystemAuditLogs)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.audit_logs")).
						Get("/stats", auditHandler.GetSystemAuditStats)
				})

				// ========== KYC ROUTES ==========
				kyc.RegisterKYCRoutes(r, kycHandler)
			})
		})
	})

	// NotFound and MethodNotAllowed handlers
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

// ==================== MIDDLEWARE FUNCTIONS ====================

func AdminSessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionType, ok := r.Context().Value("session_type").(string)
		if !ok || sessionType != "admin" {
			respondWithJWTError(w, http.StatusForbidden, "Access denied: admin session required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func EnhancedCompanyAccessMiddleware(jwtService *service.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			companyIDStr := chi.URLParam(r, "companyID")
			companyID, err := uuid.Parse(companyIDStr)
			if err != nil {
				respondWithJWTError(w, http.StatusBadRequest, "Invalid company ID")
				return
			}

			sessionType, ok := r.Context().Value("session_type").(string)
			if !ok {
				respondWithJWTError(w, http.StatusUnauthorized, "Session type not found")
				return
			}

			userIDStr, ok := r.Context().Value("user_id").(string)
			if !ok {
				respondWithJWTError(w, http.StatusUnauthorized, "User not authenticated")
				return
			}

			userID, err := uuid.Parse(userIDStr)
			if err != nil {
				respondWithJWTError(w, http.StatusBadRequest, "Invalid user ID")
				return
			}

			if sessionType != "admin" {
				validatedCompanyID, ok := r.Context().Value("validated_company_id").(string)
				if !ok || validatedCompanyID == "" {
					respondWithJWTError(w, http.StatusForbidden,
						"Company access denied: No validated company context")
					return
				}

				validatedCompanyUUID, err := uuid.Parse(validatedCompanyID)
				if err != nil {
					respondWithJWTError(w, http.StatusForbidden,
						"Company access denied: Invalid company ID in validated session")
					return
				}

				if validatedCompanyUUID != companyID {
					respondWithJWTError(w, http.StatusForbidden,
						"Company access denied: You can only access your own company")
					return
				}
			}

			ctx := context.WithValue(r.Context(), "company_id", companyID)
			ctx = context.WithValue(ctx, "current_user_id", userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func respondWithJWTError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
		"message": "Authentication failed",
		"code":    statusCode,
	})
}

// IdempotencyMiddleware reads Idempotency-Key header and stores it in request context.
func IdempotencyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		if key != "" {
			ctx := context.WithValue(r.Context(), "idempotency_key", key)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

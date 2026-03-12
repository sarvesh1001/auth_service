package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	biometricHandler "auth-service/internal/hr/biometric/handler"
	hrHandler "auth-service/internal/hr/handler"
	leavehandler "auth-service/internal/hr/leave/handler"
	middle "auth-service/internal/hr/middleware"
	payrollhandler "auth-service/internal/hr/payroll/handler"
	authMiddleware "auth-service/internal/middleware"
	"auth-service/internal/service"

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
	auditHandler *hrHandler.AuditHandler,
	employeeHandler *hrHandler.EmployeeHandler,
	schedulingHandler *hrHandler.SchedulingHandler,
	attendanceIngestHandler *hrHandler.AttendanceIngestHandler,
	pairingHandler *PairingHandler,
	workCenterHandler *hrHandler.WorkCenterHandler,
	wsHandler *WebSocketHandler,
	sessionService *service.SessionService,
	jwtService *service.JWTService,
	logger *zap.Logger,
	orgUnitHandler *hrHandler.OrgUnitHandler,
	leaveAdminHandler *leavehandler.LeaveAdminHandler,
	leaveRequestHandler *leavehandler.LeaveRequestHandler,
	leaveQueryHandler *leavehandler.LeaveQueryHandler,
	payrollRunHandler *payrollhandler.PayrollRunHandler,
	deviceHandler *hrHandler.DeviceHandler,
	attendanceAdminHandler *hrHandler.AttendanceAdminHandler,
	attendanceQueryHandler *hrHandler.AttendanceQueryHandler,
	attendanceResolutionHandler *hrHandler.AttendanceResolutionHandler,
	attendanceCorrectionHandler *hrHandler.AttendanceCorrectionHandler,
	attendanceClassHandler *hrHandler.AttendanceClassHandler,
	attendanceOMHandler *hrHandler.AttendanceOMHandler,
	attendanceDeviceEnrollmentHandler *hrHandler.AttendanceDeviceEnrollmentHandler,
	deviceHeartbeatHandler *hrHandler.DeviceHeartbeatHandler,
	attendanceBatchHandler *hrHandler.AttendanceBatchHandler,
	deviceAuthMiddleware *middle.DeviceAuthMiddleware,
	deviceTokenAdminHandler *hrHandler.DeviceTokenAdminHandler,
	attendanceSourceAdminHandler *hrHandler.AttendanceSourceAdminHandler,
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
	biometricEnrollmentHandler *biometricHandler.BiometricEnrollmentHandler,
	biometricSyncHandler *biometricHandler.BiometricSyncHandler,
	// NEW HANDLERS
	bankExportHandler *payrollhandler.BankExportHandler,
	componentHandler *payrollhandler.ComponentHandler,
	loanHandler *payrollhandler.LoanHandler,
	payslipHandler *payrollhandler.PayslipHandler,
	reportingHandler *payrollhandler.ReportingHandler,
	taxDeclarationHandler *payrollhandler.TaxDeclarationHandler,
) chi.Router {
	router := chi.NewRouter()

	router.Use(chiMiddleware.RequestID)
	router.Use(chiMiddleware.RealIP)
	router.Use(LoggerMiddleware(logger))
	router.Use(chiMiddleware.Recoverer)
	router.Use(chiMiddleware.Timeout(60 * time.Second))

	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://localhost:3000", "http://localhost:8080"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Session-Type", "X-Device-ID", "X-Company-ID", "X-Device-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Health check requested")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"service": "auth-service",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})

	router.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", adminHandler.HealthCheckHandler)

		r.Route("/setup", func(r chi.Router) {
			r.Post("/super-admin", adminHandler.InitSuperAdminHandler)
			r.Get("/super-admin/status", adminHandler.CheckSuperAdminStatusHandler)
		})

		r.Route("/admin-auth", func(r chi.Router) {
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

		authHandler.RegisterPublicRoutes(r)
		authHandler.RegisterUserPublicRoutes(r)
		otpHandler.RegisterRoutes(r)

		r.Route("/web/login", func(r chi.Router) {
			r.Get("/qr", pairingHandler.GenerateQR)
			r.Get("/status", pairingHandler.Status)
			r.Post("/confirm", pairingHandler.Confirm)
			r.Get("/ws", pairingHandler.WebSocket)
			r.With(
				authMiddleware.JWTAuthMiddlewareWithRedis(sessionService, logger),
				authMiddleware.SessionValidationMiddleware(sessionService, logger),
			).Post("/pair", pairingHandler.Pair)
		})

		r.Route("/companies/{companyID}/attendance-device", func(r chi.Router) {
			r.Route("/events", func(r chi.Router) {
				r.Use(deviceAuthMiddleware.Middleware)
				r.Use(middle.CompanyAccessMiddlewareWithDeviceSupport(jwtService, logger))
				r.Post("/punch", attendanceIngestHandler.DevicePunchAttendance)
			})
			r.Route("/batch", func(r chi.Router) {
				r.Use(deviceAuthMiddleware.MiddlewareForDeviceOnly)
				r.Use(middle.CompanyAccessMiddlewareWithDeviceSupport(jwtService, logger))
				r.Post("/ingest", attendanceBatchHandler.BatchPunch)
				r.Get("/{batch_ref}/status", attendanceBatchHandler.GetBatchStatus)
				r.Get("/{batch_ref}/failures", attendanceBatchHandler.GetBatchFailures)
			})
			r.With(
				deviceAuthMiddleware.MiddlewareForDeviceOnly,
				middle.CompanyAccessMiddlewareWithDeviceSupport(jwtService, logger),
			).Post("/device/heartbeat", deviceHeartbeatHandler.Heartbeat)
		})

		r.Route("/companies/{companyID}/biometric-device", func(r chi.Router) {
			r.Use(deviceAuthMiddleware.Middleware)
			r.Use(middle.CompanyAccessMiddlewareWithDeviceSupport(jwtService, logger))
			r.Post("/sync", biometricSyncHandler.SyncEmbeddings)
			r.Get("/full/{deviceID}", biometricSyncHandler.FullSync)
			r.Get("/incremental/{deviceID}", biometricSyncHandler.IncrementalSync)
			r.Post("/reset/{deviceID}", biometricSyncHandler.ForceDeviceResync)
			r.Get("/health", biometricSyncHandler.HealthCheck)
		})

		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.JWTAuthMiddlewareWithRedis(sessionService, logger))
			r.Use(authMiddleware.SessionValidationMiddleware(sessionService, logger))

			authHandler.RegisterProtectedRoutes(r)

			r.Route("/companies/{companyID}/employees", func(r chi.Router) {
				r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))
				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
					Post("/search", authHandler.SearchCompanyEmployees)
				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
					Get("/search/advanced", authHandler.SearchCompanyEmployeesAdvanced)
				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
					Get("/search/suggestions", authHandler.GetCompanyEmployeeSuggestions)
				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
					Get("/suggestions", authHandler.GetCompanyEmployeeSuggestions)
				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
					Get("/username/{username}", authHandler.FindCompanyEmployeeByUsername)
			})

			r.Route("/companies/{companyID}", func(r chi.Router) {
				r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

				r.Get("/", adminHandler.GetCompany)
				r.Get("/getemployees", adminHandler.GetCompanyEmployees)
				r.Get("/roles", adminHandler.GetCompanyRoles)
				r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)
				r.Get("/stats", adminHandler.GetCompanyStats)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
					Get("/departments/search", adminHandler.SearchDepartments)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
					Get("/departments/suggestions", adminHandler.GetDepartmentSuggestions)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
					Get("/info", adminHandler.GetCompanyByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
					Get("/active-departments-count", adminHandler.GetActiveDepartmentCount)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
					Get("/department-info", adminHandler.GetCompanyDepartmentInfo)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
					Get("/check-department-limit", adminHandler.CheckDepartmentLimit)

				r.Route("/positions", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.position.create", logger)).
						Post("/", adminHandler.CreatePosition)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.position.view", logger)).
						Get("/", adminHandler.ListPositions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.position.view", logger)).
						Get("/open", adminHandler.GetOpenPositions)

					r.Route("/{positionID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.position.view", logger)).
							Get("/", adminHandler.GetPosition)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.position.update", logger)).
							Put("/", adminHandler.UpdatePosition)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.position.delete", logger)).
							Delete("/", adminHandler.DeletePosition)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.position.update", logger)).
							Patch("/status", adminHandler.UpdatePositionStatus)
					})
				})

				r.Route("/departments", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware(
						"administration.company.view|hr.position.view",
						logger,
					)).Get("/root", adminHandler.GetRootDepartments)

					r.Route("/{departmentID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware(
							"administration.company.view|hr.position.view",
							logger,
						)).Get("/children", adminHandler.GetDepartmentChildren)
						r.With(authMiddleware.BitmaskPermissionMiddleware(
							"administration.company.view|hr.position.view",
							logger,
						)).Get("/tree", adminHandler.GetDepartmentTree)
						r.With(authMiddleware.BitmaskPermissionMiddleware(
							"administration.company.view|hr.position.view",
							logger,
						)).Get("/parents", adminHandler.GetDepartmentParents)
						r.With(authMiddleware.BitmaskPermissionMiddleware(
							"administration.company.view|hr.position.view",
							logger,
						)).Post("/validate-hierarchy", adminHandler.ValidateDepartmentHierarchy)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
							Put("/parent", adminHandler.UpdateDepartmentParent)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
							Post("/move", adminHandler.MoveDepartmentWithEmployees)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
							Delete("/soft", adminHandler.SoftDeleteDepartment)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
							Patch("/activate", adminHandler.ActivateDepartment)
						r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
							Post("/sub-departments", adminHandler.CreateSubDepartment)
					})

					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
						Post("/{parentDepartmentID}/sub-departments", adminHandler.CreateSubDepartment)
				})

				r.Route("/work-centers", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.view", logger)).
						Get("/", workCenterHandler.ListWorkCenters)
					r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.view", logger)).
						Get("/search", workCenterHandler.SearchWorkCenters)
					r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.view", logger)).
						Get("/active", workCenterHandler.GetActiveWorkCenters)
					r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.create", logger)).
						Post("/", workCenterHandler.CreateWorkCenter)
					r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.view", logger)).
						Get("/health", workCenterHandler.HealthCheck)

					r.Route("/{workCenterCode}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.view", logger)).
							Get("/", workCenterHandler.GetWorkCenter)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.update", logger)).
							Put("/", workCenterHandler.UpdateWorkCenter)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.delete", logger)).
							Delete("/", workCenterHandler.DeleteWorkCenter)
					})
				})

				r.Route("/payroll", func(r chi.Router) {
					// Existing payroll routes
					r.Route("/locks", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/", lockHandler.ListLocks)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.update", logger)).
							Post("/", lockHandler.CreateLock)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.update", logger)).
							Delete("/", lockHandler.DeleteLock)
					})

					r.Route("/adjustments", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/", adjHandler.ListAdjustments)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/", adjHandler.CreateAdjustment)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/bulk", adjHandler.BulkCreateAdjustments)

						r.Route("/{adjustmentID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Get("/", adjHandler.GetAdjustment)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Put("/", adjHandler.UpdateAdjustment)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Delete("/", adjHandler.DeleteAdjustment)
						})
					})

					r.Route("/structures", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/", structHandler.ListStructures)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/", structHandler.CreateStructure)

						r.Route("/{structureID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Get("/", structHandler.GetStructure)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Put("/", structHandler.UpdateStructure)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Post("/clone", structHandler.CloneStructure)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Post("/publish", structHandler.PublishStructure)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Delete("/", structHandler.DeactivateStructure)

							r.Route("/components", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
									Post("/", structHandler.AddComponent)
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
									Post("/reorder", structHandler.ReorderComponents)

								r.Route("/{componentCode}", func(r chi.Router) {
									r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
										Put("/", structHandler.UpdateComponent)
									r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
										Delete("/", structHandler.RemoveComponent)
								})
							})

						})

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/assign", structHandler.AssignToEmployee)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/assign/bulk", structHandler.BulkAssignToEmployees)
					})

					r.Route("/statutory-profiles", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Get("/components", statHandler.ListComponentDefinitions)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Post("/components", statHandler.CreateComponentDefinition)

						r.Route("/components/{statutoryCode}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Put("/", statHandler.UpdateComponentDefinition)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Delete("/", statHandler.DeleteComponentDefinition)
						})

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Get("/rule-sets", statHandler.ListRuleSets)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Post("/rule-sets", statHandler.CreateRuleSet)

						r.Route("/rule-sets/{ruleSetID}", func(r chi.Router) {

							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Put("/", statHandler.UpdateRuleSet)

							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Delete("/", statHandler.DeactivateRuleSet)

							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Post("/activate", statHandler.ActivateRuleSet)

							// =========================
							// CONTRIBUTIONS
							// =========================
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Post("/contributions", statHandler.CreateContributionRule)

							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Get("/contributions", statHandler.ListContributionRules)

							r.Route("/contributions/{ruleID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
									Put("/", statHandler.UpdateContributionRule)
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
									Delete("/", statHandler.DeleteContributionRule)
							})

							// =========================
							// TAX SLABS
							// =========================
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Post("/slabs", statHandler.CreateTaxSlab)

							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Get("/slabs", statHandler.ListTaxSlabs)

							r.Route("/slabs/{slabID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
									Put("/", statHandler.UpdateTaxSlab)
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
									Delete("/", statHandler.DeleteTaxSlab)
							})

							// =========================
							// DEDUCTION LIMITS
							// =========================
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Post("/limits", statHandler.CreateDeductionLimit)

							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Get("/limits", statHandler.ListDeductionLimits)

							r.Route("/limits/{limitID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
									Put("/", statHandler.UpdateDeductionLimit)
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
									Delete("/", statHandler.DeleteDeductionLimit)
							})

							// =========================
							// COMPONENT MAPPINGS
							// =========================
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Post("/mappings", statHandler.CreateComponentMapping)

							// ✅ NEW BULK ENDPOINT
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Post("/mappings/bulk", statHandler.BulkCreateComponentMappings)

							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Get("/mappings", statHandler.ListComponentMappings)

							r.Route("/mappings/{mappingID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
									Put("/", statHandler.UpdateComponentMapping)
								r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
									Delete("/", statHandler.DeleteComponentMapping)
							})
						})

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Get("/", statHandler.ListProfiles)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Post("/", statHandler.CreateProfile)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Post("/bulk", statHandler.BulkUpsertProfiles)

						r.Route("/{profileID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Put("/", statHandler.UpdateProfile)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
								Delete("/", statHandler.DeactivateProfile)
						})
					})

					r.Route("/attendance-rules", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/", attendanceRuleHandler.CreateRule)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/", attendanceRuleHandler.GetRules)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/active", attendanceRuleHandler.GetActiveRules)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/exists-active", attendanceRuleHandler.ExistsActiveRuleOfType)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/types/{ruleType}", attendanceRuleHandler.GetRulesByType)

						r.Route("/{ruleID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Get("/", attendanceRuleHandler.GetRuleByID)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Post("/versions", attendanceRuleHandler.UpdateRuleVersion)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Put("/activate", attendanceRuleHandler.ActivateRule)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Put("/deactivate", attendanceRuleHandler.DeactivateRule)
						})

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/bulk-deactivate-by-type", attendanceRuleHandler.BulkDeactivateByType)
					})

					r.Route("/fines", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/", employeeFineHandler.CreateFine)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/", employeeFineHandler.ListFines)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/summary", employeeFineHandler.GetCompanyFineSummary)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/bulk", employeeFineHandler.BulkCreateFines)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
							Post("/lock-for-payroll-run", employeeFineHandler.LockFinesForPayrollRun)

						r.Route("/{fineID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Get("/", employeeFineHandler.GetFineByID)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Put("/", employeeFineHandler.UpdateFine)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Delete("/", employeeFineHandler.DeleteFine)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
								Put("/process", employeeFineHandler.MarkFineAsProcessed)
						})

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Delete("/bulk/unprocessed", employeeFineHandler.BulkDeleteUnprocessed)

						r.Route("/employee/{userID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Get("/unprocessed", employeeFineHandler.GetEmployeeUnprocessedFines)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Get("/summary", employeeFineHandler.GetFineSummaryByEmployee)
						})
					})

					r.Route("/employee/{userID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/salary", compHandler.GetEmployeeSalary)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/salary/snapshot", compHandler.GetSalarySnapshot)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/earnings/preview", compHandler.PreviewEarnings)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/adjustments", adjHandler.GetEmployeeAdjustmentsForPeriod)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Get("/statutory-profiles/active", statHandler.GetEmployeeActiveProfiles)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Get("/statutory-profiles/{code}/active", statHandler.GetActiveProfile)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Get("/statutory-profiles/{code}/history", statHandler.GetProfileHistory)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Post("/tax-regime", statHandler.ChangeTaxRegime)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/history", queryHandler.GetEmployeePayrollHistory)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/ytd", queryHandler.GetEmployeeYTD)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/statutory-summary", queryHandler.GetEmployeeStatutorySummary)
					})

					r.Route("/runs", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/", queryHandler.ListRuns)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/summary", queryHandler.GetRunSummary)

						r.Route("/{runID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
								Get("/", queryHandler.GetRunExecutionStatus)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
								Get("/ledger-summary", queryHandler.GetRunLedgerSummary)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
								Get("/execution-status", queryHandler.GetRunExecutionStatus)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
								Get("/employees", queryHandler.ListEmployeesInRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
								Get("/statutory-summary", queryHandler.GetRunStatutorySummary)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
								Get("/export", queryHandler.ExportRunToCSV)

							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
								Post("/initialize", runCmdHandler.InitializeRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
								Post("/execute", runCmdHandler.ExecuteRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.approve", logger)).
								Post("/approve", runCmdHandler.ApproveRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
								Post("/mark-paid", runCmdHandler.MarkRunAsPaid)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.update", logger)).
								Post("/cancel", runCmdHandler.CancelRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
								Post("/employees/{userID}/reprocess", cmdHandler.ReprocessEmployee)

							// NEW: Bank export
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
								Get("/bank-export", bankExportHandler.GenerateBankFile)
						})

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.create", logger)).
							Post("/", runCmdHandler.CreateRun)
					})

					// NEW: Payroll components
					// Payroll components
					r.Route("/components", func(r chi.Router) {

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/", componentHandler.ListComponents)

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/default", componentHandler.GetDefaultComponent)

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/clear-cache", componentHandler.ClearCache)

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/{code}", componentHandler.GetComponent)
					})

					// Payroll component management
					r.Route("/component-management", func(r chi.Router) {

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/", payrollRunHandler.ListComponents)

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/", payrollRunHandler.CreateComponent)

						r.Route("/{componentCode}", func(r chi.Router) {

							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Put("/", payrollRunHandler.UpdateComponent)

							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
								Delete("/", payrollRunHandler.DeactivateComponent)
						})
					})
					// NEW: Loans
					// NEW: Loans
					r.Route("/loans", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/", loanHandler.CreateLoan)

						// 👇 NEW: EMI Preview
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/preview-emi", loanHandler.PreviewEMI)

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/user/{userId}", loanHandler.ListUserLoans)

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/{loanID}", loanHandler.GetLoan)

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/{loanID}/pending-emis", loanHandler.GetPendingEMIsForLoan)

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/{loanID}/close", loanHandler.CloseLoan)

						// 👇 NEW: Manual Payment
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/{loanID}/manual-payment", loanHandler.RecordManualPayment)

						// 👇 NEW: Payment Ledger
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Get("/{loanID}/payments", loanHandler.ListLoanPayments)
					})

					// NEW: EMIs under payroll runs
					r.Route("/runs/{payrollRunID}/pending-emis", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/", loanHandler.GetPendingEMIsForPayrollRun)
					})

					// NEW: EMIs paid action
					r.Route("/emis/{emiID}/paid", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
							Post("/", loanHandler.MarkEMIAsPaid)
					})

					// NEW: Payslips
					r.Route("/payslips", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
							Post("/runs/{runId}/generate", payslipHandler.GeneratePayslipsForRun)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/runs/{runId}/users/{userId}/download", payslipHandler.DownloadPayslip)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
							Post("/runs/{runId}/users/{userId}/send-email", payslipHandler.SendPayslipEmail)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/users/{userId}", payslipHandler.ListUserPayslips)
					})

					// NEW: Reports
					r.Route("/reports", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.report.view", logger)).
							Post("/statutory-challan", reportingHandler.GenerateStatutoryChallan)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.report.view", logger)).
							Post("/payroll-register", reportingHandler.GeneratePayrollRegister)
					})

					// NEW: Tax declarations
					r.Route("/tax-declarations", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Post("/types", taxDeclarationHandler.CreateDeclarationType)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Put("/types/{typeCode}", taxDeclarationHandler.UpdateDeclarationType)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.view", logger)).
							Get("/types", taxDeclarationHandler.ListDeclarationTypes)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.view", logger)).
							Get("/types/{typeCode}", taxDeclarationHandler.GetDeclarationType)

						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Post("/declarations", taxDeclarationHandler.CreateDeclaration)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Put("/declarations/{declarationID}", taxDeclarationHandler.UpdateDeclaration)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
							Post("/declarations/{declarationID}/verify", taxDeclarationHandler.VerifyDeclaration)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.view", logger)).
							Get("/declarations/user/{userID}", taxDeclarationHandler.ListDeclarationsByUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.view", logger)).
							Get("/declarations", taxDeclarationHandler.ListDeclarationsByFinancialYear)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.view", logger)).
							Get("/declarations/total", taxDeclarationHandler.GetTotalDeclaredAmount)
					})

					// Existing trend and payslip endpoints
					r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
						Get("/trend", queryHandler.GetCompanyPayrollTrend)
					r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.view", logger)).
						Get("/components/{componentCode}/trend", queryHandler.GetComponentBreakdownTrend)
					r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
						Get("/payslip/{payrollItemID}", queryHandler.GetEmployeePayslip)
				})

				r.Route("/leave", func(r chi.Router) {
					r.Route("/admin", func(r chi.Router) {
						r.Route("/policy-config", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
								Post("/", leaveAdminHandler.CreateLeavePolicy)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
								Get("/", leaveAdminHandler.ListActiveLeavePolicies)
							r.Route("/{policyID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
									Get("/", leaveAdminHandler.GetLeavePolicy)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
									Patch("/", leaveAdminHandler.UpdateLeavePolicy)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
									Delete("/", leaveAdminHandler.DeactivateLeavePolicy)
								r.Route("/rules", func(r chi.Router) {
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
										Post("/", leaveAdminHandler.AddPolicyRule)
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
										Get("/", leaveAdminHandler.GetPolicyRules)
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
										Patch("/{policyRuleID}", leaveAdminHandler.UpdatePolicyRule)
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
										Delete("/{policyRuleID}", leaveAdminHandler.DeletePolicyRule)
								})
							})
						})
						r.Route("/leave-types", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
								Get("/", leaveAdminHandler.ListLeaveTypes)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
								Post("/", leaveAdminHandler.CreateLeaveType)
							r.Route("/{leaveTypeID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
									Get("/", leaveAdminHandler.GetLeaveType)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
									Put("/", leaveAdminHandler.UpdateLeaveType)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.delete", logger)).
									Delete("/", leaveAdminHandler.DeleteLeaveType)
							})
						})
						r.Route("/entitlements", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
								Post("/", leaveAdminHandler.CreateEntitlement)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
								Get("/", leavePolicyResolutionHandler.ListEntitlements)
						})
						r.Route("/accruals", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
								Post("/monthly", leaveAdminHandler.ProcessMonthlyAccruals)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
								Get("/", leaveAdminHandler.GetAccrualsByDate)
						})
						r.Route("/recalculate", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
								Post("/{entitlementID}", leaveAdminHandler.RecalculateEntitlement)
						})
						r.Route("/policies", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
								Post("/resolve/user/{userID}", leavePolicyResolutionHandler.ResolveSingleUser)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
								Post("/resolve/batch", leavePolicyResolutionHandler.ResolveBatchUsers)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
								Get("/effective/{userID}", leavePolicyResolutionHandler.GetEffectivePolicies)
						})
					})
					r.Route("/requests", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.request", logger)).
							Post("/", leaveRequestHandler.RequestLeave)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/", leaveRequestHandler.ListLeaveRequests)
						r.Route("/{requestID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
								Get("/", leaveRequestHandler.GetLeaveRequest)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.approve", logger)).
								Post("/approve", leaveRequestHandler.ApproveLeave)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.reject", logger)).
								Post("/reject", leaveRequestHandler.RejectLeave)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.request", logger)).
								Post("/cancel", leaveRequestHandler.CancelLeave)
						})
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.approve", logger)).
							Get("/pending", leaveRequestHandler.GetPendingRequests)
					})
					r.Route("/query", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/balance", leaveQueryHandler.GetLeaveBalance)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/balance/{leaveTypeID}", leaveQueryHandler.GetLeaveBalanceByType)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/users/{userID}/balance", leaveQueryHandler.GetLeaveBalanceForUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/users/{userID}/balance/{leaveTypeID}", leaveQueryHandler.GetLeaveBalanceForUserByType)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/status", leaveQueryHandler.IsUserOnLeave)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/users/{userID}/history", leaveQueryHandler.GetUserLeaveHistory)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/users/{userID}/transactions", leaveQueryHandler.GetLeaveTransactionHistory)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/forecast", leaveQueryHandler.GetLeaveForecast)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/availability", leaveQueryHandler.CheckLeaveAvailability)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Post("/availability", leaveQueryHandler.CheckLeaveAvailability)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/report/utilization", leaveQueryHandler.GetLeaveUtilizationReport)
					})
				})

				r.Route("/attendance", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.self.punch", logger)).
						Post("/self/punch", attendanceIngestHandler.SelfPunchAttendance)
					r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.team.punch", logger)).
						Post("/punch", attendanceIngestHandler.PunchAttendance)

					r.Route("/devices", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
							Post("/", deviceHandler.CreateDevice)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/", deviceHandler.ListDevices)
						r.With(authMiddleware.BitmaskPermissionMiddleware("it.system.config.view", logger)).
							Get("/health", deviceHandler.HealthCheck)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/stats", deviceHandler.GetDeviceStatistics)

						r.Route("/{deviceID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/", deviceHandler.GetDevice)
							r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
								Put("/", deviceHandler.UpdateDevice)
							r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
								Delete("/", deviceHandler.DeleteDevice)
							r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
								Post("/activate", deviceHandler.ActivateDevice)
							r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
								Post("/deactivate", deviceHandler.DeactivateDevice)
							r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
								Post("/trust", deviceHandler.MarkAsTrusted)
							r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
								Post("/revoke-trust", deviceHandler.RevokeTrust)

							r.Route("/enrollments", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
									Post("/", attendanceDeviceEnrollmentHandler.EnrollUser)
								r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
									Delete("/", attendanceDeviceEnrollmentHandler.RevokeEnrollment)
								r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
									Post("/unrevoke", attendanceDeviceEnrollmentHandler.UnrevokeEnrollment)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
									Get("/revoked", attendanceDeviceEnrollmentHandler.GetRevokedDeviceEnrollments)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
									Get("/", attendanceDeviceEnrollmentHandler.GetDeviceEnrollments)
							})

							r.Route("/tokens", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
									Post("/", deviceTokenAdminHandler.IssueDeviceToken)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
									Get("/current", deviceTokenAdminHandler.GetCurrentDeviceToken)
								r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
									Delete("/{tokenID}", deviceTokenAdminHandler.RevokeDeviceToken)
							})
						})
					})

					r.Route("/admin", func(r chi.Router) {
						r.Route("/policies", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
								Post("/", attendanceAdminHandler.CreatePolicy)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/", attendanceAdminHandler.ListPolicies)
							r.Route("/{policyID}", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
									Get("/", attendanceAdminHandler.GetPolicy)
								r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
									Put("/", attendanceAdminHandler.UpdatePolicy)
								r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
									Delete("/", attendanceAdminHandler.DeletePolicy)
							})
						})
						r.Route("/rules", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/company", attendanceAdminHandler.GetCompanyRules)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/resolve", attendanceAdminHandler.GetResolvedRules)
						})
						r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
							Post("/assign-policy", attendanceAdminHandler.AssignPolicyToUser)
					})

					r.Route("/events", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.correct", logger)).
							Post("/correction", attendanceCorrectionHandler.CreateCorrection)
						r.Route("/{eventID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/", attendanceQueryHandler.GetEvent)
						})
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/search", attendanceQueryHandler.SearchEvents)
					})

					r.Route("/summary", func(r chi.Router) {
						r.Route("/user/{userID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/daily/{date}", attendanceQueryHandler.GetDailySummary)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/range", attendanceQueryHandler.GetUserSummaries)
						})
					})

					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
						Get("/stats", attendanceQueryHandler.GetCompanyStats)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
						Get("/stats/user/{userID}", attendanceQueryHandler.GetUserStats)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
						Get("/reports", attendanceQueryHandler.GenerateReport)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
						Get("/event-types", attendanceQueryHandler.ListEventTypes)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
						Get("/source-types", attendanceQueryHandler.ListSourceTypes)

					r.Route("/resolve", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.correct", logger)).
							Post("/event", attendanceResolutionHandler.ResolveEvent)
						r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.correct", logger)).
							Post("/day", attendanceResolutionHandler.ResolveDay)
						r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.correct", logger)).
							Post("/batch", attendanceResolutionHandler.BatchResolve)
						r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.correct", logger)).
							Post("/period", attendanceResolutionHandler.BatchResolveByPeriod)
						r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.correct", logger)).
							Post("/day/{userID}/{date}", attendanceResolutionHandler.ResolveDayByPath)
					})
				})

				r.Route("/scheduling", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("it.system.config.view", logger)).
						Get("/health", schedulingHandler.HealthCheck)

					r.Route("/calendars", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/", schedulingHandler.ListWorkCalendars)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.create", logger)).
							Post("/", schedulingHandler.CreateWorkCalendar)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/{calendarID}", schedulingHandler.GetWorkCalendar)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.update", logger)).
							Put("/{calendarID}", schedulingHandler.UpdateWorkCalendar)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.delete", logger)).
							Delete("/{calendarID}", schedulingHandler.DeleteWorkCalendar)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/{calendarID}/availability", schedulingHandler.GetCalendarAvailability)
					})

					r.Route("/holidays", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.update", logger)).
							Post("/", schedulingHandler.AddHolidayToCalendar)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.update", logger)).
							Post("/process", schedulingHandler.ProcessHolidayForDate)
					})

					r.Route("/templates", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/", schedulingHandler.ListScheduleTemplates)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.create", logger)).
							Post("/", schedulingHandler.CreateScheduleTemplate)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/{templateID}", schedulingHandler.GetScheduleTemplate)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.update", logger)).
							Put("/{templateID}", schedulingHandler.UpdateScheduleTemplate)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.delete", logger)).
							Delete("/{templateID}", schedulingHandler.DeleteScheduleTemplate)
					})

					r.Route("/instances", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/", schedulingHandler.ListScheduleInstances)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.create", logger)).
							Post("/", schedulingHandler.CreateScheduleInstance)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.create", logger)).
							Post("/bulk", schedulingHandler.BulkCreateScheduleInstances)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Post("/search", schedulingHandler.SearchScheduleInstances)

						r.Route("/{instanceID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
								Get("/", schedulingHandler.GetScheduleInstance)
							r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.update", logger)).
								Put("/{instanceID}", schedulingHandler.UpdateScheduleInstance)
							r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.delete", logger)).
								Delete("/{instanceID}", schedulingHandler.DeleteScheduleInstance)
						})
					})

					r.Route("/position-based", func(r chi.Router) {
						r.Route("/users/{userID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
								Get("/resolve", schedulingHandler.ResolveUserDay)
							r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
								Get("/position", schedulingHandler.GetUserScheduledPosition)
						})
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.create", logger)).
							Post("/instances", schedulingHandler.CreateScheduleInstanceFromPosition)
					})

					r.Route("/generate", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.create", logger)).
							Post("/user/{userID}", schedulingHandler.GenerateScheduleForUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.create", logger)).
							Post("/company", schedulingHandler.GenerateScheduleForCompany)
					})

					r.Route("/overrides", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.create", logger)).
							Post("/", schedulingHandler.CreateScheduleOverride)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/", schedulingHandler.GetScheduleOverrides)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/{overrideID}", schedulingHandler.GetScheduleOverrideByID)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.update", logger)).
							Put("/{overrideID}", schedulingHandler.UpdateScheduleOverride)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.delete", logger)).
							Delete("/{overrideID}", schedulingHandler.DeleteScheduleOverride)
					})

					r.Route("/work-centers", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.view", logger)).
							Get("/", schedulingHandler.ListWorkCenters)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.view", logger)).
							Get("/{workCenterCode}", schedulingHandler.GetWorkCenter)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.view", logger)).
							Get("/{workCenterCode}/shifts", schedulingHandler.GetWorkCenterShifts)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.view", logger)).
							Get("/{workCenterCode}/schedule", schedulingHandler.GetWorkCenterSchedule)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.assign", logger)).
							Post("/assign", schedulingHandler.AssignUserToWorkCenter)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.assign", logger)).
							Post("/assign/{assignmentID}/end", schedulingHandler.EndUserWorkCenterAssignment)
					})

					r.Route("/work-center-shifts", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.create", logger)).
							Post("/", schedulingHandler.CreateWorkCenterShiftMapping)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.update", logger)).
							Put("/", schedulingHandler.UpdateWorkCenterShiftMapping)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/", schedulingHandler.GetWorkCenterShifts)
					})

					r.Route("/positions", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.position.view", logger)).
							Get("/{positionID}/summary", schedulingHandler.GetPositionScheduleSummary)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.position.view", logger)).
							Get("/company/summaries", schedulingHandler.GetPositionSchedulesByCompany)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/{positionID}/instances", schedulingHandler.GetScheduleInstancesByPosition)
					})

					r.Route("/availability", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/check", schedulingHandler.CheckScheduleAvailability)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/conflict-check", schedulingHandler.ValidateScheduleConflict)
					})

					r.Route("/reports", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/stats", schedulingHandler.GetScheduleStats)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/coverage", schedulingHandler.GetScheduleCoverage)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/user/{userID}/summary", schedulingHandler.GetUserScheduleSummary)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/work-centers/schedules", schedulingHandler.GetWorkCenterSchedulesByCompany)
					})

					r.Route("/bulk", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.create", logger)).
							Post("/instances", schedulingHandler.BulkCreateScheduleInstances)
					})

					r.Route("/query", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Post("/search", schedulingHandler.SearchScheduleInstances)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/user/{userID}/assignment", schedulingHandler.GetUserCurrentAssignment)
					})
				})

				r.Route("/audit", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.audit.view", logger)).
						Get("/logs", auditHandler.GetCompanyAuditLogs)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.audit.view", logger)).
						Get("/entity-history", auditHandler.GetEntityAuditHistory)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.audit.view", logger)).
						Get("/export", auditHandler.ExportCompanyAuditLogs)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.audit.view", logger)).
						Get("/stats", auditHandler.GetCompanyAuditStats)
				})

				r.Route("/hr", func(r chi.Router) {
					r.Route("/employees", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/", employeeHandler.ListEmployeeProfiles)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
							Post("/", employeeHandler.CreateEmployeeProfile)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.search", logger)).
							Get("/search", employeeHandler.SearchEmployeeProfiles)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/stats", employeeHandler.GetEmployeeStats)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/export", employeeHandler.ExportEmployeeData)

						r.Route("/{employeeID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
								Get("/", employeeHandler.GetEmployeeProfile)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
								Put("/", employeeHandler.UpdateEmployeeProfile)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.delete", logger)).
								Delete("/", employeeHandler.DeleteEmployeeProfile)

							r.Route("/documents", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.view", logger)).
									Get("/", employeeHandler.GetEmployeeDocuments)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.upload", logger)).
									Post("/", employeeHandler.UploadEmployeeDocument)
								r.Route("/{documentID}", func(r chi.Router) {
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.view", logger)).
										Get("/", employeeHandler.DownloadEmployeeDocument)
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.view", logger)).
										Get("/url", employeeHandler.GenerateDocumentURL)
									r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.delete", logger)).
										Delete("/", employeeHandler.DeleteEmployeeDocument)
								})
							})

							r.Route("/department-history", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
									Get("/", employeeHandler.GetDepartmentHistory)
							})

							r.Route("/exit", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
									Get("/", employeeHandler.GetEmployeeExit)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.terminate", logger)).
									Post("/", employeeHandler.CreateEmployeeExit)
								r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.terminate", logger)).
									Post("/rehire", employeeHandler.RehireEmployee)
							})

							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
								Get("/role-history", employeeHandler.GetRoleHistory)
						})

						r.Route("/user/{userID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
								Get("/profile", employeeHandler.GetEmployeeProfileByUserID)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.view", logger)).
								Get("/documents", employeeHandler.GetEmployeeDocuments)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.document.upload", logger)).
								Post("/documents", employeeHandler.UploadEmployeeDocument)
						})
					})

					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/health", employeeHandler.HealthCheck)
				})

				r.Route("/biometric", func(r chi.Router) {
					r.Route("/face", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
							Post("/enroll", biometricEnrollmentHandler.EnrollFace)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
							Post("/re-enroll", biometricEnrollmentHandler.ReEnrollFace)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
							Post("/deactivate", biometricEnrollmentHandler.DeactivateFace)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
							Post("/activate", biometricEnrollmentHandler.ActivateFace)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/{userID}", biometricEnrollmentHandler.GetFaceEmbedding)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/", biometricEnrollmentHandler.ListActiveFaceEmbeddings)
					})
					r.Route("/model", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.system_config", logger)).
							Post("/rotate", biometricEnrollmentHandler.RotateModelVersion)
					})
				})

				r.Route("/org-units", func(r chi.Router) {
					r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/", orgUnitHandler.ListOrgUnits)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/search", orgUnitHandler.SearchOrgUnits)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/active", orgUnitHandler.GetActiveOrgUnits)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
						Post("/", orgUnitHandler.CreateOrgUnit)
					r.With(authMiddleware.BitmaskPermissionMiddleware("it.system.config.view", logger)).
						Get("/health", orgUnitHandler.HealthCheck)

					r.Route("/{orgUnitID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/", orgUnitHandler.GetOrgUnit)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
							Put("/", orgUnitHandler.UpdateOrgUnit)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.delete", logger)).
							Delete("/", orgUnitHandler.DeleteOrgUnit)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
							Post("/members", orgUnitHandler.AddMember)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/members", orgUnitHandler.GetOrgUnitMembers)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
							Post("/roles", orgUnitHandler.AssignRole)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/roles", orgUnitHandler.GetOrgUnitRoles)

						r.Route("/members/{userID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
								Put("/", orgUnitHandler.UpdateMember)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
								Delete("/", orgUnitHandler.RemoveMember)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
								Delete("/roles/{role}", orgUnitHandler.RemoveRole)
						})
					})

					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/user/{userID}/memberships", orgUnitHandler.GetUserMemberships)
				})

				r.Route("/rbac", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
						Post("/roles", rbacHandler.CreateRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
						Get("/roles", rbacHandler.ListRoles)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
						Get("/roles/{roleID}", rbacHandler.GetRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
						Put("/roles/{roleID}", rbacHandler.UpdateRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
						Delete("/roles/{roleID}", rbacHandler.DeleteRole)

					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
						Post("/employees", rbacHandler.AddEmployee)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
						Post("/managers", rbacHandler.AddManager)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
						Put("/employees/{userID}/position", rbacHandler.UpdateEmployeePosition)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/employees/{userID}", rbacHandler.GetEmployeeWithPosition)

					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
						Get("/available-permissions", rbacHandler.GetAvailablePermissions)

					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
						Post("/roles/{roleID}/permissions", rbacHandler.AssignPermissionsToRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
						Delete("/roles/{roleID}/permissions", rbacHandler.RemovePermissionsFromRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
						Get("/roles/{roleID}/permissions", rbacHandler.GetRolePermissions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
						Put("/roles/{roleID}/permissions", rbacHandler.ReplaceRolePermissions)

					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
						Get("/permissions", rbacHandler.ListAllPermissions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
						Get("/permissions/module/{module}", rbacHandler.ListPermissionsByModule)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
						Get("/permissions/name/{permissionName}", rbacHandler.GetPermissionByName)

					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
						Get("/departments", rbacHandler.ListDepartments)
					r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
						Put("/departments/{departmentID}/rename", rbacHandler.RenameDepartment)

					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/users/{userID}/permissions", rbacHandler.GetUserPermissions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/users/{userID}/permissions/bitmask", rbacHandler.GetUserPermissionBitmask)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/users/{userID}/permissions/check", rbacHandler.CheckUserPermission)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/users/{userID}/hierarchy", rbacHandler.GetUserHierarchy)

					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
						Post("/bulk-assign", rbacHandler.BulkAssignRoles)
				})
			})

			r.Route("/internal/leave", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
					Post("/resolve/onboarding", leavePolicyResolutionHandler.ResolveOnboarding)
				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
					Post("/resolve/position-change", leavePolicyResolutionHandler.ResolvePositionChange)
			})

			r.Route("/admin", func(r chi.Router) {
				r.Use(AdminSessionMiddleware(logger))

				r.Route("/admin/companies/{companyID}/attendance", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
						Get("/rules", attendanceAdminHandler.GetCompanyRules)
					r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
						Put("/rules", attendanceAdminHandler.UpdateCompanyRules)

					r.Route("/sources", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
							Get("/", attendanceSourceAdminHandler.ListSources)
						r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
							Post("/", attendanceSourceAdminHandler.CreateSource)
						r.With(authMiddleware.BitmaskPermissionMiddleware("attendance.configure", logger)).
							Put("/{sourceType}", attendanceSourceAdminHandler.UpdateSourceStatus)
					})
				})

				r.Route("/system/hr", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.system_config", logger)).
						Post("/enforce-exits", employeeHandler.EnforceEmployeeExits)
				})

				r.Route("/admins", func(r chi.Router) {
					r.Get("/stats", adminHandler.GetStats)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.create", logger)).
						Post("/", adminHandler.CreateAdminUser)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.system_config", logger)).
						Get("/{adminID}/phone", adminHandler.GetAdminPhoneNumber)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/", adminHandler.ListAdmins)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/all", adminHandler.GetAllAdmins)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/active", adminHandler.GetActiveAdmins)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/inactive", adminHandler.GetInactiveAdmins)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/role-type/{roleType}", adminHandler.GetAdminsByRoleType)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/role/{roleID}", adminHandler.GetAdminsByRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/available-managers", adminHandler.GetAvailableManagers)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/search", adminHandler.SearchAdmins)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/search/advanced", adminHandler.SearchAdminsAdvanced)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/search/name", adminHandler.SearchAdminsByName)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/search/employees", adminHandler.SearchAdminEmployees)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.manager.view", logger)).
						Get("/search/managers", adminHandler.SearchAdminManagers)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/search/suggestions", adminHandler.GetAdminSuggestions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/search/analytics", adminHandler.GetAdminSearchAnalytics)

					r.Route("/{adminID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
							Get("/", adminHandler.GetAdminUser)
						r.Get("/departments", adminHandler.GetAdminDepartments)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Put("/", adminHandler.UpdateAdminUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.delete", logger)).
							Delete("/", adminHandler.DeleteAdminUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles", logger)).
							Put("/role", adminHandler.UpdateAdminUserRole)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Put("/profile", adminHandler.UpdateAdminProfile)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Put("/phone", adminHandler.ChangeAdminPhone)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Put("/reports-to", adminHandler.UpdateAdminReportsTo)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Post("/activate", adminHandler.ActivateAdmin)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Post("/deactivate", adminHandler.DeactivateAdmin)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Post("/avatar", adminHandler.SetAdminAvatar)
						r.Get("/avatar", adminHandler.GetAdminAvatar)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Delete("/avatar", adminHandler.DeactivateAdminAvatar)
						r.Get("/avatar/with-fallback", adminHandler.GetAdminAvatarWithFallback)
						r.Get("/avatar/info", adminHandler.GetAvatarInfo)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
							Get("/direct-reports", adminHandler.GetDirectReports)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
							Get("/reporting-chain", adminHandler.GetReportingChain)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
							Get("/hierarchy", adminHandler.GetAdminHierarchy)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
							Get("/permissions", adminHandler.GetAdminPermissions)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
							Get("/permissions/mask", adminHandler.GetAdminPermissionMask)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
							Get("/permissions/check", adminHandler.CheckAdminPermission)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
							Get("/with-permissions", adminHandler.GetAdminWithPermissions)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
							Get("/details", adminHandler.GetAdminWithDetails)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
							Get("/with-reports-to-name", adminHandler.GetAdminWithReportsToName)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
							Get("/department-access/{department}", adminHandler.CheckAdminDepartmentAccess)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Post("/reset-failed-login", adminHandler.ResetAdminFailedLoginAttempts)
					})

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
						Post("/bulk-update-reports-to", adminHandler.BulkUpdateReportsTo)
				})

				r.Route("/roles", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.create", logger)).
						Post("/employee", adminHandler.CreateEmployeeRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/employee", adminHandler.GetEmployeeAdminRoles)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.manager.create", logger)).
						Post("/manager", adminHandler.CreateManagerRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.manager.view", logger)).
						Get("/manager", adminHandler.GetManagerAdminRoles)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.create", logger)).
						Post("/", adminHandler.CreateAdminRole)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/", adminHandler.GetAdminRoles)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/search", adminHandler.SearchAdminRoles)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/type/{roleType}", adminHandler.GetAdminRolesByType)

					r.Route("/{roleID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/", adminHandler.GetAdminRole)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/details", adminHandler.GetAdminRoleWithDetails)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Put("/", adminHandler.UpdateAdminRole)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.delete", logger)).
							Delete("/", adminHandler.DeleteAdminRole)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/departments", adminHandler.GetAdminRoleDepartments)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Post("/departments/{departmentID}", adminHandler.AssignDepartmentToAdminRole)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Delete("/departments/{departmentID}", adminHandler.RemoveDepartmentFromAdminRole)
					})
				})

				r.Route("/departments", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_departments", logger)).
						Get("/", adminHandler.GetSystemDepartments)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/{departmentID}/admins", adminHandler.GetAdminsByDepartment)
				})

				r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
					Post("/mpin/change-by-admin", adminHandler.ChangeAdminMPINByAdmin)

				r.Route("/user-management", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/search/advanced", adminHandler.SearchUsersAdvanced)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/search/username", adminHandler.SearchUsersByUsername)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/search/full-name", adminHandler.SearchUsersByFullName)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/suggestions", adminHandler.GetUserSuggestions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/kyc/{status}", adminHandler.ListUsersByKYCStatus)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/recently-active", adminHandler.GetRecentlyActiveUsers)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/banned", adminHandler.GetBannedUsers)

					r.Route("/{userID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Put("/", adminHandler.UpdateUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Patch("/kyc", adminHandler.UpdateUserKYC)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Post("/ban", adminHandler.BanUser)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update", logger)).
							Post("/unban", adminHandler.UnbanUser)
					})
				})

				r.Route("/companies", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.create", logger)).
						Post("/", adminHandler.CreateCompany)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/", adminHandler.GetRecentCompanies)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/search", adminHandler.SearchCompanies)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/suggestions", adminHandler.GetCompanySuggestions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/analytics/search", adminHandler.GetCompanySearchAnalytics)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
						Post("/search/benchmark", adminHandler.BenchmarkCompanySearch)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/status/{status}", adminHandler.GetCompaniesByStatus)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/tier/{tier}", adminHandler.GetCompaniesByTier)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/expiring", adminHandler.GetCompaniesWithExpiringSubscription)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/owner/{ownerID}/search", adminHandler.SearchCompaniesByOwner)

					r.Route("/{companyID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/", adminHandler.GetCompany)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/stats", adminHandler.GetCompanyStats)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/employees", adminHandler.GetCompanyEmployees)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/departments", adminHandler.GetCompanyDepartments)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/hierarchy", adminHandler.GetCompanyHierarchy)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/rbac-stats", adminHandler.GetCompanyRBACStats)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/roles", adminHandler.GetCompanyRoles)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_departments", logger)).
							Post("/", adminHandler.AdminAddDepartment)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Put("/max-departments", adminHandler.UpdateMaxDepartments)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Put("/subscription", adminHandler.UpdateSubscription)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Post("/subscription/extend", adminHandler.ExtendSubscription)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.suspend", logger)).
							Post("/deactivate", adminHandler.DeactivateCompany)
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Post("/reactivate", adminHandler.ReactivateCompany)
					})
				})

				r.Route("/system", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_departments", logger)).
						Get("/departments", adminHandler.GetSystemDepartments)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_permissions", logger)).
						Get("/permissions", adminHandler.GetAllPermissions)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_permissions", logger)).
						Get("/permissions/module/{module}", adminHandler.GetPermissionsByModule)
				})

				r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
					Post("/bulk-avatar-info", adminHandler.BulkGetAvatarInfo)

				r.Route("/audit", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.audit_logs", logger)).
						Get("/logs", auditHandler.GetSystemAuditLogs)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.audit_logs", logger)).
						Get("/export", auditHandler.ExportSystemAuditLogs)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.audit_logs", logger)).
						Get("/stats", auditHandler.GetSystemAuditStats)
				})
			})
		})
	})

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

func EnhancedCompanyAccessMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			companyIDStr := chi.URLParam(r, "companyID")
			companyID, err := uuid.Parse(companyIDStr)
			if err != nil {
				respondWithJWTError(w, logger, http.StatusBadRequest, "Invalid company ID")
				return
			}

			sessionType, ok := r.Context().Value("session_type").(string)
			if !ok {
				respondWithJWTError(w, logger, http.StatusUnauthorized, "Session type not found")
				return
			}

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

			if sessionType != "admin" {
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

			ctx := context.WithValue(r.Context(), "company_id", companyID)
			ctx = context.WithValue(ctx, "current_user_id", userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

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

			ctx = context.WithValue(ctx, "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
			ctx = context.WithValue(ctx, "jti", claims.JTI)
			if claims.PermissionMask != nil {
				ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)
			}
			if claims.CompanyID != "" {
				ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
			}
			roleType := deriveRoleTypeFromString(claims.Role)
			ctx = context.WithValue(ctx, "role_type", roleType)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func deriveRoleTypeFromString(role string) int {
	switch role {
	case "super_admin", "owner":
		return 4
	case "admin_manager", "manager":
		return 2
	case "admin_employee", "employee":
		return 1
	default:
		return 1
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
		if r.TLS == nil &&
			(strings.HasPrefix(host, "localhost") ||
				strings.HasPrefix(host, "127.0.0.1") ||
				strings.HasPrefix(host, "192.168.") ||
				strings.HasPrefix(host, "10.") ||
				strings.HasPrefix(host, "172.16.")) {
			next.ServeHTTP(w, r)
			return
		}
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

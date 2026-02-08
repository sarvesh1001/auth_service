package handler

import (
	hrHandler "auth-service/internal/hr/handler"
	leavehandler "auth-service/internal/hr/leave/handler"
	middle "auth-service/internal/hr/middleware"
	payrollhandler "auth-service/internal/hr/payroll/handler"
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
	payrollAdminHandler *payrollhandler.PayrollAdminHandler,
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
) chi.Router {
	router := chi.NewRouter()

	// Middleware stack
	router.Use(chiMiddleware.RequestID)
	router.Use(chiMiddleware.RealIP)
	router.Use(LoggerMiddleware(logger))
	router.Use(chiMiddleware.Recoverer)
	router.Use(chiMiddleware.Timeout(60 * time.Second))
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"https://*", "http://localhost:3000", "http://localhost:8080"},
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token",
			"X-Session-Type", "X-Device-ID", "X-Company-ID", "X-Device-Token",
		},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health endpoint
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Health check requested")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"service": "auth-service",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})

	// API v1 routes
	router.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", adminHandler.HealthCheckHandler)

		// Setup routes
		r.Route("/setup", func(r chi.Router) {
			r.Post("/super-admin", adminHandler.InitSuperAdminHandler)
			r.Get("/super-admin/status", adminHandler.CheckSuperAdminStatusHandler)
		})

		// Admin auth routes
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

		// Public auth routes
		authHandler.RegisterPublicRoutes(r)
		authHandler.RegisterUserPublicRoutes(r)
		otpHandler.RegisterRoutes(r)

		// Web login/pairing routes
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
				r.Post("/punch", attendanceIngestHandler.DevicePunchAttendance) // ✅ FIXED
			})

			r.Route("/batch", func(r chi.Router) {
				r.Use(deviceAuthMiddleware.MiddlewareForDeviceOnly) // ✅ REQUIRED
				r.Use(middle.CompanyAccessMiddlewareWithDeviceSupport(jwtService, logger))
				r.Post("/ingest", attendanceBatchHandler.BatchPunch)
			})

			r.With(
				deviceAuthMiddleware.MiddlewareForDeviceOnly,
				middle.CompanyAccessMiddlewareWithDeviceSupport(jwtService, logger),
			).Post("/device/heartbeat", deviceHeartbeatHandler.Heartbeat)
		})

		// JWT-protected routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.JWTAuthMiddlewareWithRedis(sessionService, logger))
			r.Use(authMiddleware.SessionValidationMiddleware(sessionService, logger))

			authHandler.RegisterProtectedRoutes(r)

			// Company employee search routes
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

			// Company routes
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

				// Positions routes
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

				// Departments routes
				r.Route("/departments", func(r chi.Router) {
					r.With(
						authMiddleware.BitmaskPermissionMiddleware(
							"administration.company.view|hr.position.view",
							logger,
						),
					).Get("/root", adminHandler.GetRootDepartments)

					r.Route("/{departmentID}", func(r chi.Router) {
						r.With(
							authMiddleware.BitmaskPermissionMiddleware(
								"administration.company.view|hr.position.view",
								logger,
							),
						).Get("/children", adminHandler.GetDepartmentChildren)
						r.With(
							authMiddleware.BitmaskPermissionMiddleware(
								"administration.company.view|hr.position.view",
								logger,
							),
						).Get("/tree", adminHandler.GetDepartmentTree)
						r.With(
							authMiddleware.BitmaskPermissionMiddleware(
								"administration.company.view|hr.position.view",
								logger,
							),
						).Get("/parents", adminHandler.GetDepartmentParents)
						r.With(
							authMiddleware.BitmaskPermissionMiddleware(
								"administration.company.view|hr.position.view",
								logger,
							),
						).Post("/validate-hierarchy", adminHandler.ValidateDepartmentHierarchy)
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

				// Work centers routes
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

				// Payroll routes
				r.Route("/payroll", func(r chi.Router) {
					r.Route("/admin", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/dashboard", payrollAdminHandler.GetAdminDashboard)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/components", payrollAdminHandler.GetPayrollComponents)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/period/check", payrollAdminHandler.CheckPeriodLock)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/period/validate", payrollAdminHandler.ValidatePeriodNotLocked)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
							Post("/period/lock", payrollAdminHandler.LockPeriod)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
							Post("/period/unlock", payrollAdminHandler.UnlockPeriod)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
							Post("/recalculate", payrollAdminHandler.ForceRecalculation)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/health", payrollAdminHandler.HealthCheck)
					})

					r.Route("/runs", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/", payrollRunHandler.ListPayrollRuns)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.create", logger)).
							Post("/", payrollRunHandler.CreatePayrollRun)
						r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
							Get("/summary", payrollRunHandler.GetRunSummary)

						r.Route("/{runID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.view", logger)).
								Get("/", payrollRunHandler.GetPayrollRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
								Post("/calculate", payrollRunHandler.CalculatePayroll)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.approve", logger)).
								Post("/approve", payrollRunHandler.ApprovePayrollRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.process", logger)).
								Post("/pay", payrollRunHandler.PayPayrollRun)
							r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.run.delete", logger)).
								Delete("/", payrollRunHandler.DeletePayrollRun)
						})
					})

					r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.component.manage", logger)).
						Post("/components", payrollAdminHandler.GetPayrollComponents)
					r.With(authMiddleware.BitmaskPermissionMiddleware("payroll.tax.manage", logger)).
						Get("/tax-profiles", payrollAdminHandler.GetPayrollComponents)
				})

				// Leave routes
				r.Route("/leave", func(r chi.Router) {
					r.Route("/admin", func(r chi.Router) {
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
							Get("/status", leaveQueryHandler.IsUserOnLeave)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/history", leaveQueryHandler.GetUserLeaveHistory)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/transactions", leaveQueryHandler.GetLeaveTransactionHistory)
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

				// 🔴 FIXED: Single attendance tree - NO shadowing
				r.Route("/attendance", func(r chi.Router) {
					// Device management routes
					r.Route("/devices", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware(
							"attendance.configure",
							logger,
						)).Post("/", deviceHandler.CreateDevice)
						r.With(authMiddleware.BitmaskPermissionMiddleware(
							"hr.attendance.view",
							logger,
						)).Get("/", deviceHandler.ListDevices)
						r.With(authMiddleware.BitmaskPermissionMiddleware(
							"it.system.config.view",
							logger,
						)).Get("/health", deviceHandler.HealthCheck)
						r.With(authMiddleware.BitmaskPermissionMiddleware(
							"hr.attendance.view",
							logger,
						)).Get("/stats", deviceHandler.GetDeviceStatistics)

						r.Route("/{deviceID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware(
								"hr.attendance.view",
								logger,
							)).Get("/", deviceHandler.GetDevice)
							r.With(authMiddleware.BitmaskPermissionMiddleware(
								"attendance.configure",
								logger,
							)).Put("/", deviceHandler.UpdateDevice)
							r.With(authMiddleware.BitmaskPermissionMiddleware(
								"attendance.configure",
								logger,
							)).Delete("/", deviceHandler.DeleteDevice)
							r.With(authMiddleware.BitmaskPermissionMiddleware(
								"attendance.configure",
								logger,
							)).Post("/activate", deviceHandler.ActivateDevice)
							r.With(authMiddleware.BitmaskPermissionMiddleware(
								"attendance.configure",
								logger,
							)).Post("/deactivate", deviceHandler.DeactivateDevice)
							r.With(authMiddleware.BitmaskPermissionMiddleware(
								"attendance.configure",
								logger,
							)).Post("/trust", deviceHandler.MarkAsTrusted)
							r.With(authMiddleware.BitmaskPermissionMiddleware(
								"attendance.configure",
								logger,
							)).Post("/revoke-trust", deviceHandler.RevokeTrust)

							r.Route("/enrollments", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware(
									"attendance.configure",
									logger,
								)).Post("/", attendanceDeviceEnrollmentHandler.EnrollUser)

								r.With(authMiddleware.BitmaskPermissionMiddleware(
									"attendance.configure",
									logger,
								)).Delete("/", attendanceDeviceEnrollmentHandler.RevokeEnrollment)

								// ✅ NEW: Unrevoke enrollment
								r.With(authMiddleware.BitmaskPermissionMiddleware(
									"attendance.configure",
									logger,
								)).Post("/unrevoke", attendanceDeviceEnrollmentHandler.UnrevokeEnrollment)

								// ✅ NEW: List revoked enrollments
								r.With(authMiddleware.BitmaskPermissionMiddleware(
									"hr.attendance.view",
									logger,
								)).Get("/revoked", attendanceDeviceEnrollmentHandler.GetRevokedDeviceEnrollments)

								r.With(authMiddleware.BitmaskPermissionMiddleware(
									"hr.attendance.view",
									logger,
								)).Get("/", attendanceDeviceEnrollmentHandler.GetDeviceEnrollments)
							})

							r.Route("/tokens", func(r chi.Router) {
								r.With(authMiddleware.BitmaskPermissionMiddleware(
									"attendance.configure",
									logger,
								)).Post("/", deviceTokenAdminHandler.IssueDeviceToken)
								r.With(authMiddleware.BitmaskPermissionMiddleware(
									"hr.attendance.view",
									logger,
								)).Get("/current", deviceTokenAdminHandler.GetCurrentDeviceToken)
								r.With(authMiddleware.BitmaskPermissionMiddleware(
									"attendance.configure",
									logger,
								)).Delete("/{tokenID}", deviceTokenAdminHandler.RevokeDeviceToken)
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
							Post("/day/{userID}/{date}", attendanceResolutionHandler.ResolveDayByPath)
					})
				})

				// Scheduling routes
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

				// Audit routes
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

				// HR routes
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

				// Org units routes
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

				// RBAC routes
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

			// Admin-only routes
			r.Route("/admin", func(r chi.Router) {
				r.Use(AdminSessionMiddleware(logger))

				r.Route("/admin/companies/{companyID}/attendance", func(r chi.Router) {

					// ===============================
					// COMPANY ATTENDANCE RULES
					// ===============================
					r.With(authMiddleware.BitmaskPermissionMiddleware(
						"attendance.configure",
						logger,
					)).Get("/rules", attendanceAdminHandler.GetCompanyRules)

					r.With(authMiddleware.BitmaskPermissionMiddleware(
						"attendance.configure",
						logger,
					)).Put("/rules", attendanceAdminHandler.UpdateCompanyRules)

					// ===============================
					// 🔥 ATTENDANCE SOURCES (ADMIN)
					// ===============================
					r.Route("/sources", func(r chi.Router) {

						// List sources
						// GET /admin/companies/{companyID}/attendance/sources
						r.With(authMiddleware.BitmaskPermissionMiddleware(
							"attendance.configure",
							logger,
						)).Get("/", attendanceSourceAdminHandler.ListSources)

						// Explicit admin create
						// POST /admin/companies/{companyID}/attendance/sources
						r.With(authMiddleware.BitmaskPermissionMiddleware(
							"attendance.configure",
							logger,
						)).Post("/", attendanceSourceAdminHandler.CreateSource)

						// Enable / Disable source
						// PUT /admin/companies/{companyID}/attendance/sources/{sourceType}
						r.With(authMiddleware.BitmaskPermissionMiddleware(
							"attendance.configure",
							logger,
						)).Put("/{sourceType}", attendanceSourceAdminHandler.UpdateSourceStatus)
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

	// 404 handler
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

	// 405 handler
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

// AdminSessionMiddleware verifies admin session
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

// EnhancedCompanyAccessMiddleware validates company access
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

// JWTAuthMiddlewareWithRedis validates JWT tokens
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

// deriveRoleTypeFromString converts role string to numeric type
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

// LoggerMiddleware logs HTTP requests
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

// requireHTTPS enforces HTTPS in production
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

// respondWithJWTError sends JWT-related errors
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

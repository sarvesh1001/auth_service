package handler

import (
	hrHandler "auth-service/internal/hr/handler"
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
	attendanceHandler *hrHandler.AttendanceHandler,
	auditHandler *hrHandler.AuditHandler,
	compensationHandler *hrHandler.CompensationHandler,
	employeeHandler *hrHandler.EmployeeHandler,
	leaveHandler *hrHandler.LeaveHandler,
	schedulingHandler *hrHandler.SchedulingHandler,
	pairingHandler *PairingHandler,
	wsHandler *WebSocketHandler,
	sessionService *service.SessionService,
	jwtService *service.JWTService,
	logger *zap.Logger,
) chi.Router {
	router := chi.NewRouter()
	router.Use(chiMiddleware.RequestID)
	router.Use(chiMiddleware.RealIP)
	router.Use(LoggerMiddleware(logger))
	router.Use(chiMiddleware.Recoverer)
	router.Use(chiMiddleware.Timeout(60 * time.Second))
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"https://*", "http://localhost:3000", "http://localhost:8080"},
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token",
			"X-Session-Type", "X-Device-ID", "X-Company-ID"},
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
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.position.delete", logger)).
							Delete("/", adminHandler.DeletePosition)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.position.update", logger)).
							Patch("/status", adminHandler.UpdatePositionStatus)
					})
				})

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

				// Updated Attendance Routes
				r.Route("/attendance", func(r chi.Router) {
					// Health Check
					r.Get("/health", attendanceHandler.HealthCheck)

					// Event Management
					r.Route("/events", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Post("/", attendanceHandler.CreateAttendanceEvent)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Post("/bulk", attendanceHandler.CreateBulkAttendanceEvents)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/{eventID}", attendanceHandler.GetAttendanceEvent)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/search", attendanceHandler.SearchAttendanceEvents)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/", attendanceHandler.GetAttendanceEventsByCompany)
						r.Route("/user/{userID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/", attendanceHandler.GetAttendanceEventsByUser)
						})
					})

					// Policy Management
					r.Route("/policies", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Post("/", attendanceHandler.CreateAttendancePolicy)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/", attendanceHandler.GetAttendancePoliciesByCompany)
						r.Route("/{policyID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/", attendanceHandler.GetAttendancePolicy)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
								Put("/", attendanceHandler.UpdateAttendancePolicy)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.delete", logger)).
								Delete("/", attendanceHandler.DeleteAttendancePolicy)
						})
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Post("/assign", attendanceHandler.AssignUserAttendancePolicy)
					})

					// Rules Management
					r.Route("/rules", func(r chi.Router) {
						// Company Rules
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/company", attendanceHandler.GetCompanyAttendanceRules)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Put("/company", attendanceHandler.UpdateCompanyAttendanceRules)

						// Department Rules
						r.Route("/departments/{departmentID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/", attendanceHandler.GetDepartmentAttendanceRules)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
								Put("/", attendanceHandler.UpdateDepartmentAttendanceRules)
						})

						// User Profile
						r.Route("/users/{userID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/profile", attendanceHandler.GetUserAttendanceProfile)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
								Put("/profile", attendanceHandler.UpdateUserAttendanceProfile)
						})

						// Rules Resolution
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/resolve", attendanceHandler.ResolveAttendanceRules)
					})

					// Summary and Reports
					r.Route("/summary", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Post("/generate", attendanceHandler.GenerateDailySummary)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Post("/generate/bulk", attendanceHandler.GenerateBulkDailySummaries)
						r.Route("/user/{userID}", func(r chi.Router) {
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/daily", attendanceHandler.GetAttendanceDailySummary)
							r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
								Get("/range", attendanceHandler.GetAttendanceDailySummaries)
						})
					})

					// Stats
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
						Get("/stats", attendanceHandler.GetAttendanceStats)
					r.Route("/stats/user/{userID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/", attendanceHandler.GetUserAttendanceStats)
					})

					// Integration
					r.Route("/integration", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Post("/sap", attendanceHandler.ProcessSAPAttendanceEvent)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Post("/factory", attendanceHandler.SyncFactoryAttendance)
					})

					// RFID Management
					r.Route("/rfid", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Post("/assign", attendanceHandler.AssignRFIDToEmployee)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/employee/{rfidTag}", attendanceHandler.GetEmployeeByRFID)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Delete("/{rfidID}", attendanceHandler.UnassignRFID)
					})

					// Work Center Management
					r.Route("/work-center", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Post("/map", attendanceHandler.MapWorkCenterToShift)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/shift/{workCenterCode}", attendanceHandler.GetShiftForWorkCenter)
					})

					// SAP Business Rules
					r.Route("/sap-rules", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
							Get("/", attendanceHandler.GetSAPBusinessRules)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.update", logger)).
							Put("/", attendanceHandler.UpdateSAPBusinessRules)
					})

					// Reports
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
						Get("/report", attendanceHandler.GenerateAttendanceReport)

					// Reference Data
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
						Get("/event-types", attendanceHandler.GetAttendanceEventTypes)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.attendance.view", logger)).
						Get("/source-types", attendanceHandler.GetAttendanceSourceTypes)
				})

				// Other HR routes remain unchanged...
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

				r.Route("/compensation", func(r chi.Router) {
					r.Route("/pay-units", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/", compensationHandler.ListPayUnitsHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/{payUnitID}", compensationHandler.GetPayUnitByIDHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
							Post("/", compensationHandler.CreatePayUnitHandler)
					})
					r.Route("/structures", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/", compensationHandler.GetCompensationStructuresByCompanyHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/search", compensationHandler.SearchCompensationStructuresHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/{structureID}", compensationHandler.GetCompensationStructureByIDHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/code/{structureCode}", compensationHandler.GetCompensationStructureByCodeHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
							Post("/", compensationHandler.CreateCompensationStructureHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
							Put("/{structureID}", compensationHandler.UpdateCompensationStructureHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.delete", logger)).
							Delete("/{structureID}", compensationHandler.DeactivateCompensationStructureHandler)
					})
					r.Route("/users", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/", compensationHandler.GetUserCompensationsByCompanyHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/search", compensationHandler.SearchUserCompensationsHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
							Post("/", compensationHandler.CreateUserCompensationHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
							Post("/bulk-assign/{structureID}", compensationHandler.BulkAssignCompensationStructureHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
							Post("/assign/{structureID}", compensationHandler.AssignCompensationStructureToUsersHandler)
					})
					r.Route("/user/{userID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/", compensationHandler.GetUserCompensationsByUserHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/current", compensationHandler.GetCurrentUserCompensationHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
							Put("/", compensationHandler.UpdateUserCompensationHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.delete", logger)).
							Post("/end", compensationHandler.EndUserCompensationHandler)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/monthly-salary", compensationHandler.CalculateUserMonthlySalaryHandler)
					})
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/stats", compensationHandler.GetCompensationStatsByCompanyHandler)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/average-ctc", compensationHandler.GetAverageCTCByDepartmentHandler)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/report", compensationHandler.GenerateCompensationReportHandler)
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/payroll", compensationHandler.CalculateMonthlyPayrollHandler)
					r.With(authMiddleware.BitmaskPermissionMiddleware("it.system.config.view", logger)).
						Get("/health", compensationHandler.HealthCheckHandler)
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

				r.Route("/leave", func(r chi.Router) {
					r.Route("/types", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/", leaveHandler.ListLeaveTypes)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/{leaveTypeID}", leaveHandler.GetLeaveType)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
							Post("/", leaveHandler.CreateLeaveType)
					})
					r.Route("/policies", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/{policyID}", leaveHandler.GetLeavePolicy)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
							Post("/", leaveHandler.CreateLeavePolicy)
					})
					r.Route("/requests", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.request", logger)).
							Post("/", leaveHandler.CreateLeaveRequest)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/", leaveHandler.ListLeaveRequests)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/{requestID}", leaveHandler.GetLeaveRequest)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.approve", logger)).
							Post("/{requestID}/approve", leaveHandler.ApproveLeaveRequest)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.reject", logger)).
							Post("/{requestID}/reject", leaveHandler.RejectLeaveRequest)
					})
					r.Route("/balance", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/", leaveHandler.GetLeaveBalance)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/user/{userID}", leaveHandler.GetEmployeeLeaveSummary)
					})
					r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
						Get("/stats", leaveHandler.GetLeaveStats)
					r.With(authMiddleware.BitmaskPermissionMiddleware("it.system.config.view", logger)).
						Get("/health", leaveHandler.HealthCheck)
				})

				r.Route("/scheduling", func(r chi.Router) {
					r.Route("/calendars", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/", schedulingHandler.ListWorkCalendars)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/{calendarID}", schedulingHandler.GetWorkCalendar)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.create", logger)).
							Post("/", schedulingHandler.CreateWorkCalendar)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/{calendarID}/availability", schedulingHandler.GetCalendarAvailability)
					})
					r.Route("/holidays", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.update", logger)).
							Post("/", schedulingHandler.DeclareHoliday)
					})
					r.Route("/time-off", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.update", logger)).
							Post("/entitlements", schedulingHandler.CreateOffEntitlement)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.view", logger)).
							Get("/entitlements/user/{userID}", schedulingHandler.GetOffEntitlements)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.request", logger)).
							Post("/requests", schedulingHandler.CreateOffRequest)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/requests", schedulingHandler.GetOffRequests)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.approve", logger)).
							Post("/requests/{requestID}/approve", schedulingHandler.ApproveOffRequest)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.approve", logger)).
							Post("/requests/{requestID}/reject", schedulingHandler.RejectOffRequest)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.create", logger)).
							Post("/overrides", schedulingHandler.CreateScheduleOverride)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/overrides", schedulingHandler.GetScheduleOverrides)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.request", logger)).
							Post("/user/{userID}/request", schedulingHandler.RequestTimeOff)
						r.With(authMiddleware.BitmaskPermissionMiddleware("hr.leave.view", logger)).
							Get("/user/{userID}/summary", schedulingHandler.GetUserTimeOffSummary)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/availability/check", schedulingHandler.CheckDateAvailability)
					})
					r.Route("/templates", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/", schedulingHandler.ListScheduleTemplates)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/{templateID}", schedulingHandler.GetScheduleTemplate)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.create", logger)).
							Post("/", schedulingHandler.CreateScheduleTemplate)
					})
					r.Route("/assignments", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.assign", logger)).
							Post("/", schedulingHandler.AssignUserToTemplate)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/user/{userID}", schedulingHandler.GetUserCurrentAssignment)
					})
					r.Route("/instances", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/", schedulingHandler.ListScheduleInstances)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/{instanceID}", schedulingHandler.GetScheduleInstance)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.task.create", logger)).
							Post("/", schedulingHandler.CreateScheduleInstance)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.create", logger)).
							Post("/generate/user/{userID}", schedulingHandler.GenerateScheduleForUser)
					})
					r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
						Get("/availability/check", schedulingHandler.CheckScheduleAvailability)
					r.Route("/reports", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/stats", schedulingHandler.GetScheduleStats)
						r.With(authMiddleware.BitmaskPermissionMiddleware("operations.shift.view", logger)).
							Get("/coverage", schedulingHandler.GetScheduleCoverage)
					})
					r.With(authMiddleware.BitmaskPermissionMiddleware("it.system.config.view", logger)).
						Get("/health", schedulingHandler.HealthCheck)
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

			r.Route("/admin", func(r chi.Router) {
				r.Use(AdminSessionMiddleware(logger))

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

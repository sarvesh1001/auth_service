package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/email"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	"auth-service/internal/hr/payroll/service/pdf"
	hrRepo "auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/locationctx"
)

type PayslipService interface {
	GeneratePayslipForEmployee(ctx context.Context, runID, userID, actorID uuid.UUID) ([]byte, error)
	GetPayslip(ctx context.Context, userID, runID uuid.UUID) ([]byte, error)
	SendPayslipEmail(ctx context.Context, companyID, runID, userID uuid.UUID) error
	ListUserPayslipSummaries(ctx context.Context, companyID, userID uuid.UUID, from, to time.Time) ([]models.PayrollRunSummary, error)
}

type payslipService struct {
	payslipRepo      repository.PayslipRepository
	employeeRepo     hrRepo.EmployeeRepository // 👈 new
	emailSender      email.Sender
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewPayslipService(
	payslipRepo repository.PayslipRepository,
	employeeRepo hrRepo.EmployeeRepository, // 👈 new
	emailSender email.Sender,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) PayslipService {
	return &payslipService{
		payslipRepo:      payslipRepo,
		employeeRepo:     employeeRepo,
		emailSender:      emailSender,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// ensureEmployeeInScope — same helper as the rest of the payroll services.
func (s *payslipService) ensureEmployeeInScope(
	ctx context.Context,
	companyID, targetUserID uuid.UUID,
) error {
	if actorStr, ok := ctx.Value("user_id").(string); ok {
		if actorID, err := uuid.Parse(actorStr); err == nil && actorID == targetUserID {
			return nil
		}
	}
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return nil // system call
	}
	if locCtx.Mode == locationctx.ScopeAll {
		return nil
	}
	empLoc, err := s.employeeRepo.GetEmploymentLocationID(ctx, companyID, targetUserID)
	if err != nil {
		return err
	}
	if empLoc == nil {
		return ErrEmployeeHasNoLocation
	}
	if *empLoc != *locCtx.LocationID {
		return ErrEmployeeOutsideScope
	}
	return nil
}

// GeneratePayslipForEmployee — employee-scoped; validate target.
func (s *payslipService) GeneratePayslipForEmployee(ctx context.Context, runID, userID, actorID uuid.UUID) ([]byte, error) {
	data, err := s.payslipRepo.GetPayslipData(ctx, runID, userID)
	if err != nil {
		return nil, fmt.Errorf("get payslip data: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("no payroll data found for run %s and user %s", runID, userID)
	}

	// 👇 Location scope check — validates target user belongs to caller's scope
	if err := s.ensureEmployeeInScope(ctx, data.CompanyID, userID); err != nil {
		return nil, err
	}

	pdfData, err := pdf.GeneratePayslip(data)
	if err != nil {
		return nil, fmt.Errorf("generate PDF: %w", err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx, nil, &data.CompanyID, "payroll", "payslip.generate", "payroll_run",
		&runID, "user", &actorID, nil, nil,
		map[string]interface{}{
			"ip":      ip,
			"user_id": userID.String(),
			"run_id":  runID.String(),
		},
	)

	return pdfData, nil
}

// GetPayslip — validate target after loading data.
func (s *payslipService) GetPayslip(ctx context.Context, userID, runID uuid.UUID) ([]byte, error) {
	systemActor := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	return s.GeneratePayslipForEmployee(ctx, runID, userID, systemActor)
}

// SendPayslipEmail — employee-scoped write with idempotency.
func (s *payslipService) SendPayslipEmail(ctx context.Context, companyID, runID, userID uuid.UUID) error {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("payslip_email-%s-%s", runID.String(), userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	emailAddr, err := s.payslipRepo.GetEmployeeEmail(ctx, companyID, userID)
	if err != nil {
		return fmt.Errorf("get employee email: %w", err)
	}
	if emailAddr == "" {
		return fmt.Errorf("employee email not found")
	}

	pdfData, err := s.GetPayslip(ctx, userID, runID)
	if err != nil {
		return fmt.Errorf("generate payslip PDF: %w", err)
	}

	data, err := s.payslipRepo.GetPayslipData(ctx, runID, userID)
	if err != nil {
		return fmt.Errorf("get payslip data for email: %w", err)
	}
	if data == nil {
		return fmt.Errorf("no payslip data found for run %s user %s", runID, userID)
	}

	periodStr := fmt.Sprintf("%s to %s",
		data.PeriodStart.Format("02 Jan 2006"),
		data.PeriodEnd.Format("02 Jan 2006"),
	)
	subject := fmt.Sprintf("Payslip for %s", periodStr)
	body := fmt.Sprintf(`
	<html>
	<body>
		<p>Dear %s,</p>
		<p>Please find attached your payslip for the period <strong>%s</strong>.</p>
		<p>Thank you,<br>HR Team</p>
	</body>
	</html>
	`, data.EmployeeName, periodStr)

	filename := fmt.Sprintf("payslip_%s_%s.pdf", runID.String()[:8], userID.String()[:8])
	attachment := email.Attachment{
		Filename: filename,
		Data:     pdfData,
	}

	if err := s.emailSender.Send(emailAddr, subject, body, attachment); err != nil {
		return fmt.Errorf("send email: %w", err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "payroll", "payslip.email_sent", "payroll_run",
		&runID, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":       ip,
			"user_id":  userID.String(),
			"run_id":   runID.String(),
			"email_to": emailAddr,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ListUserPayslipSummaries — employee-scoped read.
func (s *payslipService) ListUserPayslipSummaries(ctx context.Context, companyID, userID uuid.UUID, from, to time.Time) ([]models.PayrollRunSummary, error) {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	summaries, err := s.payslipRepo.ListPayrollRunsForUser(ctx, companyID, userID, from, to)
	if err != nil {
		return nil, err
	}
	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "payroll", "payslip.list", "payroll_run",
		nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":      ip,
			"user_id": userID.String(),
			"from":    from,
			"to":      to,
			"count":   len(summaries),
		},
	)
	return summaries, nil
}

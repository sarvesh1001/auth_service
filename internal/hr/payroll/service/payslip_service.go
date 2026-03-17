package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/email" // add this import
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	"auth-service/internal/hr/payroll/service/pdf"
)

type PayslipService interface {
	// GeneratePayslipForEmployee generates a PDF payslip for a single employee.
	GeneratePayslipForEmployee(ctx context.Context, runID, userID, actorID uuid.UUID) ([]byte, error)

	// GetPayslip returns the payslip PDF for a given run and user (generates on the fly).
	GetPayslip(ctx context.Context, userID, runID uuid.UUID) ([]byte, error)

	// SendPayslipEmail generates the payslip PDF and sends it to the employee's email address.
	SendPayslipEmail(ctx context.Context, companyID, runID, userID uuid.UUID) error

	// ListUserPayslipSummaries returns summary information about all payslips available for a user.
	ListUserPayslipSummaries(ctx context.Context, companyID, userID uuid.UUID, from, to time.Time) ([]models.PayrollRunSummary, error)
}

type payslipService struct {
	payslipRepo repository.PayslipRepository
	emailSender email.Sender // added email sender
	logger      *zap.Logger
}

// NewPayslipService now expects an email.Sender.
func NewPayslipService(
	payslipRepo repository.PayslipRepository,
	emailSender email.Sender,
	logger *zap.Logger,
) PayslipService {
	return &payslipService{
		payslipRepo: payslipRepo,
		emailSender: emailSender,
		logger:      logger.Named("payslip_service"),
	}
}

func (s *payslipService) GeneratePayslipForEmployee(ctx context.Context, runID, userID, actorID uuid.UUID) ([]byte, error) {
	// Fetch data
	data, err := s.payslipRepo.GetPayslipData(ctx, runID, userID)
	if err != nil {
		return nil, fmt.Errorf("get payslip data: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("no payroll data found for run %s and user %s", runID, userID)
	}

	// Generate PDF
	pdfData, err := pdf.GeneratePayslip(data)
	if err != nil {
		return nil, fmt.Errorf("generate PDF: %w", err)
	}

	return pdfData, nil
}

func (s *payslipService) GetPayslip(ctx context.Context, userID, runID uuid.UUID) ([]byte, error) {
	// Always generate on the fly. Use a system actor ID for generation (not stored).
	systemActor := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	return s.GeneratePayslipForEmployee(ctx, runID, userID, systemActor)
}

// SendPayslipEmail implements the email sending functionality.
func (s *payslipService) SendPayslipEmail(ctx context.Context, companyID, runID, userID uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "SendPayslipEmail"),
		zap.String("company_id", companyID.String()),
		zap.String("run_id", runID.String()),
		zap.String("user_id", userID.String()),
	)

	logger.Debug("starting send payslip email process")

	// 1. Get employee email
	emailAddr, err := s.payslipRepo.GetEmployeeEmail(ctx, companyID, userID)
	if err != nil {
		logger.Error("failed to get employee email", zap.Error(err))
		return fmt.Errorf("get employee email: %w", err)
	}

	if emailAddr == "" {
		logger.Error("employee email is empty")
		return fmt.Errorf("employee email not found")
	}

	logger.Debug("employee email retrieved", zap.String("email", emailAddr))

	// 2. Generate payslip PDF
	pdfData, err := s.GetPayslip(ctx, userID, runID)
	if err != nil {
		logger.Error("failed to generate payslip PDF", zap.Error(err))
		return fmt.Errorf("generate payslip PDF: %w", err)
	}

	logger.Debug("payslip PDF generated", zap.Int("size_bytes", len(pdfData)))

	// 3. Fetch payslip data for email subject/body
	data, err := s.payslipRepo.GetPayslipData(ctx, runID, userID)
	if err != nil {
		logger.Error("failed to get payslip data for email", zap.Error(err))
		return fmt.Errorf("get payslip data for email: %w", err)
	}

	if data == nil {
		logger.Error("payslip data not found")
		return fmt.Errorf("no payslip data found for run %s user %s", runID, userID)
	}

	logger.Debug("payslip data retrieved",
		zap.Time("period_start", data.PeriodStart),
		zap.Time("period_end", data.PeriodEnd),
	)

	// 4. Prepare email content
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

	// 5. Prepare attachment
	filename := fmt.Sprintf("payslip_%s_%s.pdf", runID.String()[:8], userID.String()[:8])

	attachment := email.Attachment{
		Filename: filename,
		Data:     pdfData,
	}

	logger.Debug("email prepared",
		zap.String("to", emailAddr),
		zap.String("subject", subject),
		zap.String("attachment", filename),
	)

	// 6. Send email
	err = s.emailSender.Send(emailAddr, subject, body, attachment)
	if err != nil {
		logger.Error("failed to send email",
			zap.String("email", emailAddr),
			zap.Error(err),
		)
		return fmt.Errorf("send email: %w", err)
	}

	logger.Info("payslip email sent successfully",
		zap.String("email", emailAddr),
	)

	return nil
}

func (s *payslipService) ListUserPayslipSummaries(ctx context.Context, companyID, userID uuid.UUID, from, to time.Time) ([]models.PayrollRunSummary, error) {
	return s.payslipRepo.ListPayrollRunsForUser(ctx, companyID, userID, from, to)
}

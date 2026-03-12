package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
)

// PDFGenerator defines the interface for creating payslip PDFs.

// ObjectStorage defines the interface for storing and retrieving files.
type ObjectStorage interface {
	Upload(ctx context.Context, key string, data []byte, contentType string) error
	Download(ctx context.Context, key string) ([]byte, error)
}

// EmailSender defines the interface for sending emails with attachments.
type EmailSender interface {
	SendPayslipEmail(to, subject, body string, attachment []byte, attachmentName string) error
}

// PayslipService handles all payslip operations.
type PayslipService interface {
	// GeneratePayslipsForRun creates PDF payslips for all employees in a payroll run,
	// uploads them to object storage, and stores records in the database.
	GeneratePayslipsForRun(ctx context.Context, payrollRunID uuid.UUID, actorID uuid.UUID) error

	// GetPayslip returns the PDF bytes of a specific payslip.
	GetPayslip(ctx context.Context, userID uuid.UUID, payrollRunID uuid.UUID) ([]byte, error)

	// SendPayslipEmail sends the payslip as an email attachment to the employee.
	SendPayslipEmail(ctx context.Context, payslipID uuid.UUID) error

	// ListUserPayslips returns all payslip records for a given user within a date range.
	ListUserPayslips(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, from, to time.Time) ([]models.PayslipRecord, error)
}

type payslipService struct {
	payslipRepo repository.PayslipRepository
	payrollRepo repository.PayrollRepository
	bankRepo    repository.BankDetailsRepository // optional, for bank details on payslip
	pdfGen      PDFGenerator
	storage     ObjectStorage
	emailSender EmailSender
	logger      *zap.Logger
}

// NewPayslipService creates a new payslip service.
func NewPayslipService(
	payslipRepo repository.PayslipRepository,
	payrollRepo repository.PayrollRepository,
	bankRepo repository.BankDetailsRepository,
	pdfGen PDFGenerator,
	storage ObjectStorage,
	emailSender EmailSender,
	logger *zap.Logger,
) PayslipService {
	return &payslipService{
		payslipRepo: payslipRepo,
		payrollRepo: payrollRepo,
		bankRepo:    bankRepo,
		pdfGen:      pdfGen,
		storage:     storage,
		emailSender: emailSender,
		logger:      logger.Named("payslip_service"),
	}
}

// GeneratePayslipsForRun generates payslips for all employees in a payroll run.
// It is idempotent: if a payslip already exists for a user, it is skipped.
func (s *payslipService) GeneratePayslipsForRun(ctx context.Context, payrollRunID uuid.UUID, actorID uuid.UUID) error {
	// 1. Fetch payroll run and validate its status.
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, payrollRunID)
	if err != nil {
		return fmt.Errorf("failed to get payroll run: %w", err)
	}
	if run == nil {
		return errors.New("payroll run not found")
	}
	// Payslips should only be generated after approval (or payment).
	if run.Status != models.PayrollStatusApproved && run.Status != models.PayrollStatusPaid {
		return fmt.Errorf("cannot generate payslips for run in status %s", run.Status)
	}

	// 2. Get all payroll items (active) for this run.
	items, err := s.payrollRepo.GetPayrollItemsByRun(ctx, payrollRunID)
	if err != nil {
		return fmt.Errorf("failed to get payroll items: %w", err)
	}

	var failures int
	for _, item := range items {
		// 3. Check if a payslip already exists for this user/run.
		existing, _ := s.payslipRepo.GetByRunAndUser(ctx, payrollRunID, item.UserID)
		if existing != nil {
			s.logger.Debug("payslip already exists, skipping",
				zap.String("user_id", item.UserID.String()))
			continue
		}

		// 4. Get detailed payroll item (includes ledger components).
		detail, err := s.payrollRepo.GetPayrollItemDetail(ctx, item.PayrollItemID)
		if err != nil {
			failures++
			s.logger.Error("failed to get payroll item detail",
				zap.Error(err),
				zap.String("item_id", item.PayrollItemID.String()),
				zap.String("user_id", item.UserID.String()))
			continue
		}

		// 5. Build the payslip data model.
		payslipData := &models.Payslip{
			PayslipID:    uuid.New(),
			CompanyID:    run.CompanyID,
			UserID:       item.UserID,
			PayrollRunID: payrollRunID,
			PeriodStart:  run.PeriodStart,
			PeriodEnd:    run.PeriodEnd,
			Earnings:     []models.PayslipComponent{},
			Deductions:   []models.PayslipComponent{},
			GrossAmount:  item.GrossAmount,
			NetAmount:    item.NetAmount,
			GeneratedAt:  time.Now().UTC(),
		}

		// 6. Separate components into earnings and deductions, and compute total tax.
		var totalTax float64
		for _, comp := range detail.Components {
			pc := models.PayslipComponent{
				Code:        comp.ComponentCode,
				Description: comp.Description,
				Amount:      comp.Amount,
			}
			if comp.ComponentType == models.ComponentTypeEarning {
				payslipData.Earnings = append(payslipData.Earnings, pc)
			} else {
				payslipData.Deductions = append(payslipData.Deductions, pc)
				if comp.IsTaxable && (comp.ComponentCode == "TAX" || comp.ComponentCode == "TDS") {
					totalTax += comp.Amount
				}
			}
		}
		payslipData.TotalTax = totalTax

		// 7. Generate PDF.
		pdfBytes, err := s.pdfGen.GeneratePayslipPDF(payslipData)
		if err != nil {
			failures++
			s.logger.Error("failed to generate payslip PDF",
				zap.Error(err),
				zap.String("user_id", item.UserID.String()))
			continue
		}

		// 8. Upload to object storage.
		objectKey := fmt.Sprintf("payslips/%s/%s/%s.pdf",
			run.CompanyID.String(),
			payrollRunID.String(),
			item.UserID.String())
		if err := s.storage.Upload(ctx, objectKey, pdfBytes, "application/pdf"); err != nil {
			failures++
			s.logger.Error("failed to upload payslip PDF",
				zap.Error(err),
				zap.String("user_id", item.UserID.String()))
			continue
		}

		// 9. Save record in database.
		record := &models.PayslipRecord{
			PayslipID:    payslipData.PayslipID,
			PayrollRunID: payrollRunID,
			UserID:       item.UserID,
			PDFObjectKey: objectKey,
			GeneratedAt:  payslipData.GeneratedAt,
		}
		if err := s.payslipRepo.Create(ctx, record); err != nil {
			failures++
			s.logger.Error("failed to save payslip record",
				zap.Error(err),
				zap.String("user_id", item.UserID.String()))
			// Optionally delete the uploaded file? Not necessary for now.
			continue
		}
	}

	if failures > 0 {
		return fmt.Errorf("payslip generation completed with %d failures", failures)
	}
	return nil
}

// GetPayslip retrieves the PDF for a specific payslip.
func (s *payslipService) GetPayslip(ctx context.Context, userID uuid.UUID, payrollRunID uuid.UUID) ([]byte, error) {
	record, err := s.payslipRepo.GetByRunAndUser(ctx, payrollRunID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get payslip record: %w", err)
	}
	if record == nil {
		return nil, errors.New("payslip not found")
	}
	return s.storage.Download(ctx, record.PDFObjectKey)
}

// SendPayslipEmail sends the payslip as an email attachment to the employee.
// This implementation assumes the employee's email can be fetched from the user service.
// For now, it returns a "not implemented" error.
func (s *payslipService) SendPayslipEmail(ctx context.Context, payslipID uuid.UUID) error {
	// TODO: Implement after adding GetByID to repository and fetching employee email.
	return errors.New("SendPayslipEmail not yet implemented")
}

// ListUserPayslips returns all payslip records for a user within a date range.
func (s *payslipService) ListUserPayslips(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, from, to time.Time) ([]models.PayslipRecord, error) {
	return s.payslipRepo.ListByUser(ctx, companyID, userID, from, to)
}

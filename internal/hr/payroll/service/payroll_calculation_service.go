package service

import (
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	"auth-service/internal/util"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type PayrollCalculationService interface {
	CalculateRun(ctx context.Context, run *models.PayrollRun) error
	CalculateEmployeePayroll(ctx context.Context, runID, userID uuid.UUID) error
	RecalculateEmployee(ctx context.Context, runID, userID uuid.UUID) error
}

type payrollCalculationService struct {
	repo            repository.PayrollRepository
	compensationSvc CompensationResolver
	taxEngine       TaxEngine
	logger          *zap.Logger
}

func NewPayrollCalculationService(
	repo repository.PayrollRepository,
	compensationSvc CompensationResolver,
	taxEngine TaxEngine,
	logger *zap.Logger,
) PayrollCalculationService {
	return &payrollCalculationService{
		repo:            repo,
		compensationSvc: compensationSvc,
		taxEngine:       taxEngine,
		logger:          logger,
	}
}

func (s *payrollCalculationService) CalculateRun(
	ctx context.Context,
	run *models.PayrollRun,
) error {

	employeeIDs, err := s.repo.GetEmployeeIDsForPayroll(
		ctx,
		run.CompanyID,
		run.PeriodStart,
		run.PeriodEnd,
	)
	if err != nil {
		return err
	}

	for _, userID := range employeeIDs {
		if err := s.CalculateEmployeePayroll(ctx, run.PayrollRunID, userID); err != nil {
			s.logger.Error("Payroll calculation failed for employee",
				util.String("user_id", userID.String()),
				util.String("run_id", run.PayrollRunID.String()),
				util.ErrorField(err),
			)
		}
	}

	return nil
}

func (s *payrollCalculationService) CalculateEmployeePayroll(
	ctx context.Context,
	runID, userID uuid.UUID,
) error {

	run, err := s.repo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil {
		return fmt.Errorf("payroll run not found")
	}

	totalDays, payableDays, err := s.repo.GetPayrollAttendanceDays(
		ctx,
		run.CompanyID,
		userID,
		run.PeriodStart,
		run.PeriodEnd,
	)
	if err != nil {
		return err
	}

	unpaidDays := totalDays - payableDays

	compensation, err := s.compensationSvc.ResolveCompensation(
		ctx,
		run.CompanyID,
		userID,
		run.PeriodStart,
		run.PeriodEnd,
		payableDays,
	)
	if err != nil {
		return err
	}

	deductions, err := s.calculateDeductions(ctx, run.CompanyID, compensation)
	if err != nil {
		return err
	}

	gross := s.calculateGrossAmount(compensation)
	deductionTotal := s.calculateDeductionAmount(deductions)
	net := gross - deductionTotal

	payrollItem := &models.PayrollItem{
		PayrollItemID: uuid.New(),
		PayrollRunID:  runID,
		UserID:        userID,
		PayableDays:   payableDays,
		UnpaidDays:    unpaidDays,
		GrossAmount:   gross,
		NetAmount:     net,
		CreatedAt:     time.Now().UTC(),
	}

	if err := s.repo.CreatePayrollItem(ctx, payrollItem); err != nil {
		return err
	}

	ledgerEntries := s.createLedgerEntries(
		payrollItem.PayrollItemID,
		compensation,
		deductions,
	)

	for _, entry := range ledgerEntries {
		if err := s.repo.CreateLedgerEntry(ctx, entry); err != nil {
			return err
		}
	}

	return nil
}

func (s *payrollCalculationService) RecalculateEmployee(
	ctx context.Context,
	runID, userID uuid.UUID,
) error {

	items, err := s.repo.GetPayrollItemsByRun(ctx, runID)
	if err != nil {
		return err
	}

	for _, item := range items {
		if item.UserID == userID {
			if err := s.repo.DeletePayrollItem(ctx, item.PayrollItemID); err != nil {
				return err
			}
			break
		}
	}

	return s.CalculateEmployeePayroll(ctx, runID, userID)
}

func (s *payrollCalculationService) calculateGrossAmount(
	comp []*models.PayrollLedgerItem,
) float64 {
	var total float64
	for _, c := range comp {
		if c.ComponentType == models.ComponentTypeEarning {
			total += c.Amount
		}
	}
	return total
}

func (s *payrollCalculationService) calculateDeductionAmount(
	items []*models.PayrollLedgerItem,
) float64 {
	var total float64
	for _, d := range items {
		total += d.Amount
	}
	return total
}

func (s *payrollCalculationService) calculateDeductions(
	ctx context.Context,
	companyID uuid.UUID,
	comp []*models.PayrollLedgerItem,
) ([]*models.PayrollLedgerItem, error) {

	var taxable float64
	for _, c := range comp {
		if c.IsTaxable && c.ComponentType == models.ComponentTypeEarning {
			taxable += c.Amount
		}
	}

	components, err := s.repo.GetComponents(ctx, models.ComponentFilter{
		ComponentType: util.StringPtr(models.ComponentTypeDeduction),
		IsActive:      util.BoolPtr(true),
	})
	if err != nil {
		return nil, err
	}

	var deductions []*models.PayrollLedgerItem
	for _, comp := range components {
		amount, err := s.taxEngine.ApplyTaxRules(
			ctx,
			companyID,
			comp.ComponentCode,
			taxable,
		)
		if err != nil || amount <= 0 {
			continue
		}

		deductions = append(deductions, &models.PayrollLedgerItem{
			ComponentCode: comp.ComponentCode,
			ComponentType: comp.ComponentType,
			Description:   comp.Description,
			Amount:        amount,
			IsTaxable:     comp.IsTaxable,
		})
	}

	return deductions, nil
}

func (s *payrollCalculationService) createLedgerEntries(
	itemID uuid.UUID,
	comp, ded []*models.PayrollLedgerItem,
) []*models.PayrollLedger {

	now := time.Now().UTC()
	var entries []*models.PayrollLedger

	for _, c := range comp {
		entries = append(entries, &models.PayrollLedger{
			LedgerID:      uuid.New(),
			PayrollItemID: itemID,
			ComponentCode: c.ComponentCode,
			Amount:        c.Amount,
			CreatedAt:     now,
		})
	}

	for _, d := range ded {
		entries = append(entries, &models.PayrollLedger{
			LedgerID:      uuid.New(),
			PayrollItemID: itemID,
			ComponentCode: d.ComponentCode,
			Amount:        d.Amount,
			CreatedAt:     now,
		})
	}

	return entries
}

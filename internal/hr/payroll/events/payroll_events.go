package events

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PayrollEvent represents outbox events for payroll operations
type PayrollEvent struct {
	EventID     uuid.UUID  `json:"event_id"`
	EventType   string     `json:"event_type"`
	AggregateID uuid.UUID  `json:"aggregate_id"` // payroll_run_id or payroll_item_id
	Payload     []byte     `json:"payload"`      // JSON payload
	CreatedAt   time.Time  `json:"created_at"`
	ProcessedAt *time.Time `json:"processed_at,omitempty"`
}

// PayrollEventPublisher interface for publishing payroll events
type PayrollEventPublisher interface {
	PublishRunCreated(ctx context.Context, runID, companyID uuid.UUID, periodStart, periodEnd time.Time, createdBy *uuid.UUID) error
	PublishRunCalculated(ctx context.Context, runID, companyID uuid.UUID) error
	PublishRunApproved(ctx context.Context, runID, companyID, approvedBy uuid.UUID) error
	PublishRunPaid(ctx context.Context, runID, companyID, paidBy uuid.UUID) error
	PublishEmployeePayrollCalculated(ctx context.Context, runID, userID, companyID uuid.UUID, gross, net float64) error
	PublishPayrollLocked(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time, lockedBy uuid.UUID) error
	PublishPayrollUnlocked(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time, unlockedBy uuid.UUID) error
}

// payrollEventPublisher implements PayrollEventPublisher
type payrollEventPublisher struct {
	logger *zap.Logger
}

func NewPayrollEventPublisher(logger *zap.Logger) PayrollEventPublisher {
	return &payrollEventPublisher{
		logger: logger,
	}
}

func (p *payrollEventPublisher) PublishRunCreated(ctx context.Context, runID, companyID uuid.UUID, periodStart, periodEnd time.Time, createdBy *uuid.UUID) error {
	event := PayrollEvent{
		EventID:     uuid.New(),
		EventType:   "payroll.run.created",
		AggregateID: runID,
		Payload:     []byte(`{"status":"draft"}`),
		CreatedAt:   time.Now().UTC(),
	}
	// In production, this would publish to Kafka/RabbitMQ or write to outbox table
	p.logger.Info("Payroll run created event",
		zap.String("event_type", event.EventType),
		zap.String("run_id", runID.String()),
		zap.String("company_id", companyID.String()))
	return nil
}

func (p *payrollEventPublisher) PublishRunCalculated(ctx context.Context, runID, companyID uuid.UUID) error {
	event := PayrollEvent{
		EventID:     uuid.New(),
		EventType:   "payroll.run.calculated",
		AggregateID: runID,
		Payload:     []byte(`{"status":"calculated"}`),
		CreatedAt:   time.Now().UTC(),
	}
	p.logger.Info("Payroll run calculated event",
		zap.String("event_type", event.EventType),
		zap.String("run_id", runID.String()))
	return nil
}

func (p *payrollEventPublisher) PublishRunApproved(ctx context.Context, runID, companyID, approvedBy uuid.UUID) error {
	event := PayrollEvent{
		EventID:     uuid.New(),
		EventType:   "payroll.run.approved",
		AggregateID: runID,
		Payload:     []byte(`{"status":"approved"}`),
		CreatedAt:   time.Now().UTC(),
	}
	p.logger.Info("Payroll run approved event",
		zap.String("event_type", event.EventType),
		zap.String("run_id", runID.String()),
		zap.String("approved_by", approvedBy.String()))
	return nil
}

func (p *payrollEventPublisher) PublishRunPaid(ctx context.Context, runID, companyID, paidBy uuid.UUID) error {
	event := PayrollEvent{
		EventID:     uuid.New(),
		EventType:   "payroll.run.paid",
		AggregateID: runID,
		Payload:     []byte(`{"status":"paid"}`),
		CreatedAt:   time.Now().UTC(),
	}
	p.logger.Info("Payroll run paid event",
		zap.String("event_type", event.EventType),
		zap.String("run_id", runID.String()),
		zap.String("paid_by", paidBy.String()))
	return nil
}

func (p *payrollEventPublisher) PublishEmployeePayrollCalculated(ctx context.Context, runID, userID, companyID uuid.UUID, gross, net float64) error {
	// This would typically be a batch event for all employees
	return nil
}

func (p *payrollEventPublisher) PublishPayrollLocked(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time, lockedBy uuid.UUID) error {
	event := PayrollEvent{
		EventID:     uuid.New(),
		EventType:   "payroll.period.locked",
		AggregateID: companyID,
		CreatedAt:   time.Now().UTC(),
	}
	p.logger.Info("Payroll period locked event",
		zap.String("event_type", event.EventType),
		zap.String("company_id", companyID.String()))
	return nil
}

func (p *payrollEventPublisher) PublishPayrollUnlocked(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time, unlockedBy uuid.UUID) error {
	event := PayrollEvent{
		EventID:     uuid.New(),
		EventType:   "payroll.period.unlocked",
		AggregateID: companyID,
		CreatedAt:   time.Now().UTC(),
	}
	p.logger.Info("Payroll period unlocked event",
		zap.String("event_type", event.EventType),
		zap.String("company_id", companyID.String()))
	return nil
}

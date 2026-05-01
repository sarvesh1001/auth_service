package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/events"
	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/models/compliance"
	"auth-service/internal/accounting/models/enums"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// -----------------------------------------------------------------------------
// Custom errors for compliance domain
// -----------------------------------------------------------------------------

var (
	ErrOverpayment = fmt.Errorf("overpayment: total paid exceeds liability")
)

// TopicAccountingEvents must be defined elsewhere (e.g., constants.go)
// If not, define it here:
// const TopicAccountingEvents = "accounting.events"

// -----------------------------------------------------------------------------
// Request DTOs (must match those used in the service)
// -----------------------------------------------------------------------------

type CreateReturnRequest struct {
	CompanyID   uuid.UUID
	ReturnType  string
	PeriodStart time.Time
	PeriodEnd   time.Time
	DueDate     time.Time
	CreatedBy   *uuid.UUID
	UpdatedBy   *uuid.UUID
}

type UpdateReturnRequest struct {
	ReturnID  uuid.UUID
	DueDate   *time.Time
	UpdatedBy *uuid.UUID
}

type FileReturnRequest struct {
	AcknowledgementNo   *string
	PaymentAmount       *decimal.Decimal
	TaxPayableAccountID uuid.UUID
	BankAccountID       uuid.UUID
	Metadata            []byte
	FiledBy             *uuid.UUID
}

type AmendReturnRequest struct {
	AmendedBy *uuid.UUID
}

// Pagination is already defined in repository; we alias it for convenience.

// -----------------------------------------------------------------------------
// TransactionalJournalService – allows journal creation within an existing tx
// -----------------------------------------------------------------------------

type TransactionalJournalService interface {
	CreateWithTx(ctx context.Context, tx *sql.Tx, req CreateJournalRequest) (*models.JournalEntry, error)
	PostWithTx(ctx context.Context, tx *sql.Tx, id uuid.UUID, postedBy *uuid.UUID) error // add this line
}

// CreateJournalRequest and JournalLineRequest must be defined elsewhere
// (they come from the journal service). For completeness, we include minimal
// definitions here if not already present.

// -----------------------------------------------------------------------------
// ComplianceService interface
// -----------------------------------------------------------------------------

type ComplianceService interface {
	CreateReturn(ctx context.Context, req CreateReturnRequest) (*compliance.ComplianceReturn, error)
	UpdateReturn(ctx context.Context, req UpdateReturnRequest) (*compliance.ComplianceReturn, error)
	SubmitReturn(ctx context.Context, id uuid.UUID, submittedBy *uuid.UUID) error
	FileReturn(ctx context.Context, id uuid.UUID, req FileReturnRequest) (*compliance.ComplianceFiling, error)
	AmendReturn(ctx context.Context, id uuid.UUID, req AmendReturnRequest) (*compliance.ComplianceReturn, error)
	DeleteReturn(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	GetReturnByID(ctx context.Context, id uuid.UUID) (*compliance.ComplianceReturn, error)
	ListReturns(ctx context.Context, filter repository.ComplianceReturnFilter, p Pagination) ([]*compliance.ComplianceReturn, int64, error)
	GetFilingByID(ctx context.Context, id uuid.UUID) (*compliance.ComplianceFiling, error)
	UpdateFilingStatus(ctx context.Context, filingID uuid.UUID, status enums.ComplianceFilingStatus, errorMessage *string) error
}

// -----------------------------------------------------------------------------
// complianceService implementation
// -----------------------------------------------------------------------------

type complianceService struct {
	repo             repository.ComplianceRepository
	taxEngine        TaxEngineService
	journalService   TransactionalJournalService
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewComplianceService(
	repo repository.ComplianceRepository,
	taxEngine TaxEngineService,
	journalService TransactionalJournalService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) ComplianceService {
	return &complianceService{
		repo:             repo,
		taxEngine:        taxEngine,
		journalService:   journalService,
		pgClient:         pgClient,
		logger:           logger.Named("compliance_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// -----------------------------------------------------------------------------
// CreateReturn
// -----------------------------------------------------------------------------

func (s *complianceService) CreateReturn(ctx context.Context, req CreateReturnRequest) (*compliance.ComplianceReturn, error) {
	logger := s.logger.With(zap.String("method", "CreateReturn"), zap.String("company_id", req.CompanyID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateReturnRequest(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing *compliance.ComplianceReturn
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	exists, err := s.repo.ExistsReturnForPeriod(ctx, tx, req.CompanyID, req.ReturnType, req.PeriodStart, req.PeriodEnd)
	if err != nil {
		return nil, fmt.Errorf("check period uniqueness: %w", err)
	}
	if exists {
		return nil, ErrConflict
	}

	liability, lines, err := s.taxEngine.ComputePeriodLiability(ctx, req.CompanyID, req.PeriodStart, req.PeriodEnd)
	if err != nil {
		return nil, fmt.Errorf("compute liability: %w", err)
	}

	ret := &compliance.ComplianceReturn{
		ReturnID:       uuid.New(),
		CompanyID:      req.CompanyID,
		ReturnType:     req.ReturnType,
		PeriodStart:    req.PeriodStart,
		PeriodEnd:      req.PeriodEnd,
		DueDate:        req.DueDate,
		Status:         string(enums.ReturnStatusDraft),
		TotalLiability: liability,
		TotalPaid:      decimal.Zero,
		IsLocked:       false,
		CreatedBy:      req.CreatedBy,
		UpdatedBy:      req.UpdatedBy,
		AmendedFrom:    nil,
	}

	if err := s.repo.CreateReturn(ctx, tx, ret); err != nil {
		return nil, fmt.Errorf("create return: %w", err)
	}

	returnLines := make([]*compliance.ComplianceReturnLine, len(lines))
	for i, l := range lines {
		returnLines[i] = &compliance.ComplianceReturnLine{
			LineID:        uuid.New(),
			ReturnID:      ret.ReturnID,
			LineType:      l.LineType,
			TaxRateID:     l.TaxRateID,
			TaxableAmount: l.TaxableAmount,
			TaxAmount:     l.TaxAmount,
			Description:   l.Description,
		}
	}
	if err := s.repo.BulkAddReturnLines(ctx, tx, returnLines); err != nil {
		return nil, fmt.Errorf("add lines: %w", err)
	}

	payload, _ := json.Marshal(events.ComplianceReturnPayload{
		ReturnID:       ret.ReturnID.String(),
		CompanyID:      ret.CompanyID.String(),
		ReturnType:     ret.ReturnType,
		PeriodStart:    ret.PeriodStart,
		PeriodEnd:      ret.PeriodEnd,
		DueDate:        ret.DueDate,
		Status:         ret.Status,
		TotalLiability: ret.TotalLiability.String(),
		TotalPaid:      ret.TotalPaid.String(),
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "compliance_return",
		AggregateID:   ret.ReturnID.String(),
		EventType:     events.EventReturnCreated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, ret)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "compliance", "create", "compliance_return",
			&ret.ReturnID, "user", req.CreatedBy, nil, nil, nil)
	}

	logger.Info("compliance return created", zap.String("return_id", ret.ReturnID.String()))
	return ret, nil
}

// -----------------------------------------------------------------------------
// UpdateReturn
// -----------------------------------------------------------------------------

func (s *complianceService) UpdateReturn(ctx context.Context, req UpdateReturnRequest) (*compliance.ComplianceReturn, error) {
	logger := s.logger.With(zap.String("method", "UpdateReturn"), zap.String("return_id", req.ReturnID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing *compliance.ComplianceReturn
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	oldReturn, err := s.repo.GetReturnByIDForUpdate(ctx, tx, req.ReturnID)
	if err != nil {
		return nil, fmt.Errorf("get return: %w", err)
	}
	if oldReturn == nil {
		return nil, fmt.Errorf("%w: return %s", ErrNotFound, req.ReturnID)
	}

	// Only draft returns can be updated
	if oldReturn.Status != string(enums.ReturnStatusDraft) {
		return nil, fmt.Errorf("%w: cannot update return in status %s", ErrInvalidState, oldReturn.Status)
	}

	oldStateJSON, _ := json.Marshal(oldReturn)

	if req.DueDate != nil {
		oldReturn.DueDate = *req.DueDate
	}
	oldReturn.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateReturn(ctx, tx, oldReturn); err != nil {
		return nil, fmt.Errorf("update return: %w", err)
	}

	payload, _ := json.Marshal(events.ComplianceReturnPayload{
		ReturnID:       oldReturn.ReturnID.String(),
		CompanyID:      oldReturn.CompanyID.String(),
		ReturnType:     oldReturn.ReturnType,
		PeriodStart:    oldReturn.PeriodStart,
		PeriodEnd:      oldReturn.PeriodEnd,
		DueDate:        oldReturn.DueDate,
		Status:         oldReturn.Status,
		TotalLiability: oldReturn.TotalLiability.String(),
		TotalPaid:      oldReturn.TotalPaid.String(),
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "compliance_return",
		AggregateID:   oldReturn.ReturnID.String(),
		EventType:     events.EventReturnUpdated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, oldReturn)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	newStateJSON, _ := json.Marshal(oldReturn)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &oldReturn.CompanyID, "compliance", "update", "compliance_return",
			&oldReturn.ReturnID, "user", req.UpdatedBy, oldStateJSON, newStateJSON, nil)
	}

	logger.Info("compliance return updated")
	return oldReturn, nil
}

// -----------------------------------------------------------------------------
// SubmitReturn
// -----------------------------------------------------------------------------

func (s *complianceService) SubmitReturn(ctx context.Context, id uuid.UUID, submittedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "SubmitReturn"), zap.String("return_id", id.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var processed bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
			logger.Info("idempotent request, already submitted")
			return nil
		}
	}

	ret, err := s.repo.GetReturnByIDForUpdate(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get return: %w", err)
	}
	if ret == nil {
		return fmt.Errorf("%w: return %s", ErrNotFound, id)
	}
	if ret.Status != string(enums.ReturnStatusDraft) {
		return fmt.Errorf("%w: cannot submit return in status %s", ErrInvalidState, ret.Status)
	}

	oldStateJSON, _ := json.Marshal(ret)

	if err := s.repo.UpdateReturnStatus(ctx, tx, id, enums.ReturnStatusSubmitted, submittedBy); err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	ret.Status = string(enums.ReturnStatusSubmitted)

	payload, _ := json.Marshal(events.ComplianceReturnPayload{
		ReturnID:       ret.ReturnID.String(),
		CompanyID:      ret.CompanyID.String(),
		ReturnType:     ret.ReturnType,
		PeriodStart:    ret.PeriodStart,
		PeriodEnd:      ret.PeriodEnd,
		DueDate:        ret.DueDate,
		Status:         ret.Status,
		TotalLiability: ret.TotalLiability.String(),
		TotalPaid:      ret.TotalPaid.String(),
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "compliance_return",
		AggregateID:   ret.ReturnID.String(),
		EventType:     events.EventReturnSubmitted,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	newStateJSON, _ := json.Marshal(ret)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &ret.CompanyID, "compliance", "submit", "compliance_return",
			&id, "user", submittedBy, oldStateJSON, newStateJSON, nil)
	}

	logger.Info("compliance return submitted")
	return nil
}

// -----------------------------------------------------------------------------
// FileReturn
// -----------------------------------------------------------------------------

func (s *complianceService) FileReturn(ctx context.Context, id uuid.UUID, req FileReturnRequest) (*compliance.ComplianceFiling, error) {
	logger := s.logger.With(zap.String("method", "FileReturn"), zap.String("return_id", id.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing *compliance.ComplianceFiling
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached filing")
			return existing, nil
		}
	}

	ret, err := s.repo.GetReturnByIDForUpdate(ctx, tx, id)
	if err != nil {
		return nil, fmt.Errorf("get return: %w", err)
	}
	if ret == nil {
		return nil, fmt.Errorf("%w: return %s", ErrNotFound, id)
	}
	if ret.Status != string(enums.ReturnStatusSubmitted) {
		return nil, fmt.Errorf("%w: cannot file return in status %s", ErrInvalidState, ret.Status)
	}

	oldStateJSON, _ := json.Marshal(ret)

	if req.PaymentAmount != nil && !req.PaymentAmount.IsZero() {
		newTotalPaid := ret.TotalPaid.Add(*req.PaymentAmount)
		if newTotalPaid.GreaterThan(ret.TotalLiability) {
			return nil, ErrOverpayment
		}

		journalReq := CreateJournalRequest{
			CompanyID:   ret.CompanyID,
			JournalType: enums.JournalTypePayment,
			EntryDate:   time.Now(),
			Reference:   stringPtr(fmt.Sprintf("Tax payment for return %s", ret.ReturnID.String())),
			Description: stringPtr(fmt.Sprintf("Payment of %s for period %s to %s", req.PaymentAmount.String(), ret.PeriodStart.Format("2006-01-02"), ret.PeriodEnd.Format("2006-01-02"))),
			Lines: []JournalLineRequest{
				{AccountID: req.TaxPayableAccountID, DebitAmount: *req.PaymentAmount, CreditAmount: decimal.Zero},
				{AccountID: req.BankAccountID, DebitAmount: decimal.Zero, CreditAmount: *req.PaymentAmount},
			},
			CreatedBy: req.FiledBy,
			UpdatedBy: req.FiledBy,
		}
		journalEntry, err := s.journalService.CreateWithTx(ctx, tx, journalReq)
		if err != nil {
			return nil, fmt.Errorf("create payment journal: %w", err)
		}
		// 🔥 CRITICAL FIX: Post the journal immediately so ledger entries are created
		if err := s.journalService.PostWithTx(ctx, tx, journalEntry.JournalEntryID, req.FiledBy); err != nil {
			return nil, fmt.Errorf("post payment journal: %w", err)
		}
		ret.TotalPaid = newTotalPaid
		if err := s.repo.UpdateReturn(ctx, tx, ret); err != nil {
			return nil, fmt.Errorf("update paid amount: %w", err)
		}
	}

	filing := &compliance.ComplianceFiling{
		FilingID:          uuid.New(),
		ReturnID:          ret.ReturnID,
		SubmissionDate:    time.Now(),
		AcknowledgementNo: req.AcknowledgementNo,
		FilingStatus:      string(enums.FilingStatusPending),
		ErrorMessage:      nil,
		Metadata:          req.Metadata,
		CreatedBy:         req.FiledBy,
	}
	if err := s.repo.CreateFiling(ctx, tx, filing); err != nil {
		return nil, fmt.Errorf("create filing: %w", err)
	}

	// 🔥 Mark return as filed right away (synchronous)
	if err := s.repo.UpdateReturnStatus(ctx, tx, ret.ReturnID, enums.ReturnStatusFiled, req.FiledBy); err != nil {
		return nil, fmt.Errorf("update return status to filed: %w", err)
	}
	ret.Status = string(enums.ReturnStatusFiled)

	// Outbox events
	returnPayload, _ := json.Marshal(events.ComplianceReturnPayload{
		ReturnID:       ret.ReturnID.String(),
		CompanyID:      ret.CompanyID.String(),
		ReturnType:     ret.ReturnType,
		PeriodStart:    ret.PeriodStart,
		PeriodEnd:      ret.PeriodEnd,
		DueDate:        ret.DueDate,
		Status:         ret.Status,
		TotalLiability: ret.TotalLiability.String(),
		TotalPaid:      ret.TotalPaid.String(),
	})
	filingPayload, _ := json.Marshal(events.ComplianceFilingPayload{
		FilingID:          filing.FilingID.String(),
		ReturnID:          filing.ReturnID.String(),
		SubmissionDate:    filing.SubmissionDate,
		AcknowledgementNo: getStringValue(filing.AcknowledgementNo),
		FilingStatus:      string(filing.FilingStatus),
		ErrorMessage:      getStringValue(filing.ErrorMessage),
	})
	for _, evt := range []*outbox.Event{
		{EventID: uuid.New().String(), AggregateType: "compliance_return", AggregateID: ret.ReturnID.String(), EventType: events.EventReturnFiled, Payload: returnPayload, Status: "pending", Topic: TopicAccountingEvents},
		{EventID: uuid.New().String(), AggregateType: "compliance_filing", AggregateID: filing.FilingID.String(), EventType: events.EventFilingCreated, Payload: filingPayload, Status: "pending", Topic: TopicAccountingEvents},
	} {
		if err := s.outboxRepo.Store(ctx, tx, evt); err != nil {
			return nil, fmt.Errorf("store outbox event: %w", err)
		}
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, filing)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	newStateJSON, _ := json.Marshal(ret)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &ret.CompanyID, "compliance", "file", "compliance_return",
			&id, "user", req.FiledBy, oldStateJSON, newStateJSON, map[string]interface{}{"acknowledgement_no": req.AcknowledgementNo})
	}

	logger.Info("compliance return filing completed", zap.String("filing_id", filing.FilingID.String()))
	return filing, nil
}

// -----------------------------------------------------------------------------
// AmendReturn
// -----------------------------------------------------------------------------

func (s *complianceService) AmendReturn(ctx context.Context, id uuid.UUID, req AmendReturnRequest) (*compliance.ComplianceReturn, error) {
	logger := s.logger.With(zap.String("method", "AmendReturn"), zap.String("original_return_id", id.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing *compliance.ComplianceReturn
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached amended return")
			return existing, nil
		}
	}

	original, err := s.repo.GetReturnByIDForUpdate(ctx, tx, id)
	if err != nil {
		return nil, fmt.Errorf("get original return: %w", err)
	}
	if original == nil {
		return nil, fmt.Errorf("%w: return %s", ErrNotFound, id)
	}
	if original.Status != string(enums.ReturnStatusFiled) {
		return nil, fmt.Errorf("%w: only filed returns can be amended", ErrInvalidState)
	}

	oldStateJSON, _ := json.Marshal(original)

	liability, lines, err := s.taxEngine.ComputePeriodLiability(ctx, original.CompanyID, original.PeriodStart, original.PeriodEnd)
	if err != nil {
		return nil, fmt.Errorf("recompute liability: %w", err)
	}

	amended := &compliance.ComplianceReturn{
		ReturnID:       uuid.New(),
		CompanyID:      original.CompanyID,
		ReturnType:     original.ReturnType,
		PeriodStart:    original.PeriodStart,
		PeriodEnd:      original.PeriodEnd,
		DueDate:        original.DueDate,
		Status:         string(enums.ReturnStatusDraft),
		TotalLiability: liability,
		TotalPaid:      original.TotalPaid,
		IsLocked:       false,
		CreatedBy:      req.AmendedBy,
		UpdatedBy:      req.AmendedBy,
		AmendedFrom:    &original.ReturnID,
	}

	if err := s.repo.CreateReturn(ctx, tx, amended); err != nil {
		return nil, fmt.Errorf("create amended return: %w", err)
	}

	returnLines := make([]*compliance.ComplianceReturnLine, len(lines))
	for i, l := range lines {
		returnLines[i] = &compliance.ComplianceReturnLine{
			LineID:        uuid.New(),
			ReturnID:      amended.ReturnID,
			LineType:      l.LineType,
			TaxRateID:     l.TaxRateID,
			TaxableAmount: l.TaxableAmount,
			TaxAmount:     l.TaxAmount,
			Description:   l.Description,
		}
	}
	if err := s.repo.BulkAddReturnLines(ctx, tx, returnLines); err != nil {
		return nil, fmt.Errorf("add lines: %w", err)
	}

	if err := s.repo.UpdateReturnStatus(ctx, tx, original.ReturnID, enums.ReturnStatusAmended, req.AmendedBy); err != nil {
		return nil, fmt.Errorf("update original status to amended: %w", err)
	}

	payload, _ := json.Marshal(events.ComplianceReturnPayload{
		ReturnID:       amended.ReturnID.String(),
		CompanyID:      amended.CompanyID.String(),
		ReturnType:     amended.ReturnType,
		PeriodStart:    amended.PeriodStart,
		PeriodEnd:      amended.PeriodEnd,
		DueDate:        amended.DueDate,
		Status:         amended.Status,
		TotalLiability: amended.TotalLiability.String(),
		TotalPaid:      amended.TotalPaid.String(),
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "compliance_return",
		AggregateID:   amended.ReturnID.String(),
		EventType:     events.EventReturnAmended,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, amended)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	newStateJSON, _ := json.Marshal(amended)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &original.CompanyID, "compliance", "amend", "compliance_return",
			&id, "user", req.AmendedBy, oldStateJSON, newStateJSON, map[string]interface{}{"amended_return_id": amended.ReturnID.String()})
	}

	logger.Info("compliance return amended", zap.String("amended_id", amended.ReturnID.String()))
	return amended, nil
}

// -----------------------------------------------------------------------------
// DeleteReturn
// -----------------------------------------------------------------------------

func (s *complianceService) DeleteReturn(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteReturn"), zap.String("return_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ret, err := s.repo.GetReturnByIDForUpdate(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get return: %w", err)
	}
	if ret == nil {
		return fmt.Errorf("%w: return %s", ErrNotFound, id)
	}
	if ret.Status == string(enums.ReturnStatusFiled) {
		return fmt.Errorf("%w: cannot delete a filed return", ErrInvalidState)
	}
	if ret.IsLocked {
		return fmt.Errorf("%w: cannot delete a locked return", ErrInvalidState)
	}

	oldStateJSON, _ := json.Marshal(ret)

	if err := s.repo.DeleteReturn(ctx, tx, id, deletedBy); err != nil {
		return fmt.Errorf("delete return: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	newStateJSON, _ := json.Marshal(map[string]interface{}{"deleted": true})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &ret.CompanyID, "compliance", "delete", "compliance_return",
			&id, "user", deletedBy, oldStateJSON, newStateJSON, nil)
	}
	logger.Info("compliance return soft-deleted")
	return nil
}

// -----------------------------------------------------------------------------
// UpdateFilingStatus
// -----------------------------------------------------------------------------

func (s *complianceService) UpdateFilingStatus(ctx context.Context, filingID uuid.UUID, status enums.ComplianceFilingStatus, errorMessage *string) error {
	logger := s.logger.With(zap.String("method", "UpdateFilingStatus"), zap.String("filing_id", filingID.String()))

	if status != enums.FilingStatusAccepted && status != enums.FilingStatusRejected && status != enums.FilingStatusPending {
		return fmt.Errorf("%w: invalid filing status %s", ErrInvalidInput, status)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	filing, err := s.repo.GetFilingByID(ctx, tx, filingID)
	if err != nil {
		return fmt.Errorf("get filing: %w", err)
	}
	if filing == nil {
		return fmt.Errorf("%w: filing %s", ErrNotFound, filingID)
	}

	if err := s.repo.UpdateFilingStatus(ctx, tx, filingID, status, errorMessage); err != nil {
		return fmt.Errorf("update filing status: %w", err)
	}

	if status == enums.FilingStatusAccepted {
		if err := s.repo.UpdateReturnStatus(ctx, tx, filing.ReturnID, enums.ReturnStatusFiled, nil); err != nil {
			return fmt.Errorf("update return status to filed: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "compliance", "update_filing_status", "compliance_filing",
			&filingID, "system", nil, nil, nil, map[string]interface{}{"status": status, "error_message": errorMessage})
	}
	logger.Info("filing status updated", zap.String("status", string(status)))
	return nil
}

// -----------------------------------------------------------------------------
// Query methods
// -----------------------------------------------------------------------------

func (s *complianceService) GetReturnByID(ctx context.Context, id uuid.UUID) (*compliance.ComplianceReturn, error) {
	ret, err := s.repo.GetReturnByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if ret == nil {
		return nil, fmt.Errorf("%w: return %s", ErrNotFound, id)
	}
	return ret, nil
}

func (s *complianceService) ListReturns(ctx context.Context, filter repository.ComplianceReturnFilter, p Pagination) ([]*compliance.ComplianceReturn, int64, error) {
	limit, offset := s.validatePagination(p)
	sort := repository.Sort{Field: "period_start", Direction: "DESC"}
	items, err := s.repo.ListReturns(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: limit, Offset: offset}, sort)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.CountReturns(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (s *complianceService) GetFilingByID(ctx context.Context, id uuid.UUID) (*compliance.ComplianceFiling, error) {
	filing, err := s.repo.GetFilingByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if filing == nil {
		return nil, fmt.Errorf("%w: filing %s", ErrNotFound, id)
	}
	return filing, nil
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

func (s *complianceService) validateReturnRequest(req CreateReturnRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", ErrInvalidInput)
	}
	if req.ReturnType == "" {
		return fmt.Errorf("%w: return_type required", ErrInvalidInput)
	}
	if req.PeriodStart.IsZero() || req.PeriodEnd.IsZero() {
		return fmt.Errorf("%w: period_start and period_end required", ErrInvalidInput)
	}
	if req.PeriodStart.After(req.PeriodEnd) {
		return fmt.Errorf("%w: period_start must be before period_end", ErrInvalidInput)
	}
	if req.DueDate.IsZero() {
		return fmt.Errorf("%w: due_date required", ErrInvalidInput)
	}
	return nil
}

func (s *complianceService) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// stringPtr is already defined in journal_service.go; we reuse it.
// If not available, uncomment below:
// func stringPtr(s string) *string { return &s }

func getStringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// FeeService defines all fee-related business operations.
type FeeService interface {
	// Fee structure
	CreateFeeStructure(ctx context.Context, req CreateFeeStructureRequest, idempotencyKey string) (*models.FeeStructure, error)
	GetFeeStructureByID(ctx context.Context, id uuid.UUID) (*models.FeeStructure, error)
	ListFeeStructures(ctx context.Context, filter repository.FeeStructureFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.FeeStructure, error)
	UpdateFeeStructure(ctx context.Context, req UpdateFeeStructureRequest) (*models.FeeStructure, error)
	DeleteFeeStructure(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	// Fee structure items
	AddFeeStructureItem(ctx context.Context, feeStructureID uuid.UUID, req CreateFeeStructureItemRequest) (*models.FeeStructureItem, error)
	UpdateFeeStructureItem(ctx context.Context, req UpdateFeeStructureItemRequest) error
	DeleteFeeStructureItem(ctx context.Context, itemID uuid.UUID) error

	// Invoices
	CreateInvoice(ctx context.Context, req CreateInvoiceRequest) (*models.StudentFeeInvoice, error)
	GetInvoiceByID(ctx context.Context, id uuid.UUID) (*models.StudentFeeInvoice, error)
	GetInvoiceByNumber(ctx context.Context, invoiceNo string) (*models.StudentFeeInvoice, error)
	ListInvoices(ctx context.Context, filter repository.InvoiceFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.StudentFeeInvoice, error)
	UpdateInvoiceStatus(ctx context.Context, id uuid.UUID, status string, updatedBy *uuid.UUID) error

	// Payments
	CreatePayment(ctx context.Context, req CreatePaymentRequest) (*models.StudentFeePayment, error)
	GetPaymentByID(ctx context.Context, id uuid.UUID) (*models.StudentFeePayment, error)
	GetPaymentsByInvoice(ctx context.Context, invoiceID uuid.UUID) ([]*models.StudentFeePayment, error)
	ListPayments(ctx context.Context, filter repository.PaymentFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.StudentFeePayment, error)
	GenerateReceipt(ctx context.Context, paymentID uuid.UUID, receiptNo string, idempotencyKey string) (*models.FeeReceipt, error)

	// Discounts
	CreateDiscount(ctx context.Context, req CreateDiscountRequest) (*models.FeeDiscount, error)
	UpdateDiscount(ctx context.Context, req UpdateDiscountRequest) (*models.FeeDiscount, error)
	DeleteDiscount(ctx context.Context, id uuid.UUID) error

	// Penalties
	CreatePenalty(ctx context.Context, req CreatePenaltyRequest) (*models.FeePenalty, error)
	UpdatePenalty(ctx context.Context, req UpdatePenaltyRequest) (*models.FeePenalty, error)

	// Receipts
	GetReceiptByNumber(ctx context.Context, receiptNo string) (*models.FeeReceipt, error)
}

type feeService struct {
	repo             repository.FeeRepository
	studentRepo      repository.StudentRepository
	academicYearRepo repository.AcademicYearRepository
	courseRepo       repository.CourseRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	notifSvc         NotificationService // added
}

func NewFeeService(
	repo repository.FeeRepository,
	studentRepo repository.StudentRepository,
	academicYearRepo repository.AcademicYearRepository,
	courseRepo repository.CourseRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	notifSvc NotificationService, // added
) FeeService {
	return &feeService{
		repo:             repo,
		studentRepo:      studentRepo,
		academicYearRepo: academicYearRepo,
		courseRepo:       courseRepo,
		pgClient:         pgClient,
		logger:           logger.Named("fee_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		notifSvc:         notifSvc,
	}
}

// ---------- Helper for notifications ----------
func (s *feeService) sendNotificationToStudent(ctx context.Context, studentID uuid.UUID, title, message string, notifType models.NotificationType, priority models.NotificationPriority, createdBy *uuid.UUID) {
	if s.notifSvc == nil {
		return
	}
	// Get student details to obtain company ID
	student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, studentID)
	if err != nil || student == nil {
		s.logger.Warn("failed to get student for notification",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		return
	}
	targets := []NotificationTargetInput{
		{TargetType: models.TargetStudent, TargetEntityID: studentID},
	}
	req := CreateNotificationRequest{
		CompanyID: student.CompanyID,
		Title:     title,
		Message:   message,
		Type:      notifType,
		Priority:  priority,
		Targets:   targets,
		CreatedBy: createdBy,
	}
	// Use background context to avoid cancellation of main request
	_, err = s.notifSvc.Create(context.Background(), req, "")
	if err != nil {
		s.logger.Error("failed to send notification", zap.Error(err))
	}
}

// ---------- Fee structure ----------
func (s *feeService) CreateFeeStructure(ctx context.Context, req CreateFeeStructureRequest, idempotencyKey string) (*models.FeeStructure, error) {
	logger := s.logger.With(
		zap.String("method", "CreateFeeStructure"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("name", req.FeeStructureName),
	)

	if key, ok := ctx.Value("idempotency_key").(string); ok && key != "" && idempotencyKey == "" {
		idempotencyKey = key
	}
	if idempotencyKey != "" {
		var existing *models.FeeStructure
		if err := s.idempotencyStore.Get(ctx, nil, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	if err := s.validateFeeStructureInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Validate that the referenced entities exist
	if err := s.validateFeeStructureReferences(ctx, tx, req); err != nil {
		return nil, err
	}

	fs := &models.FeeStructure{
		AcademicYearID:   req.AcademicYearID,
		CourseID:         req.CourseID,
		SectionID:        req.SectionID,
		FeeStructureName: req.FeeStructureName,
		TotalAmount:      req.TotalAmount,
		IsActive:         req.IsActive,
		CreatedBy:        req.CreatedBy,
		UpdatedBy:        req.UpdatedBy,
	}

	if err := s.repo.CreateFeeStructure(ctx, tx, fs); err != nil {
		return nil, err
	}

	// Store outbox event
	payload, _ := json.Marshal(fs)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fee_structure",
		AggregateID:   fs.FeeStructureID.String(),
		EventType:     string(EventFeeStructureCreated),
		Topic:         TopicStudent, // <-- ADD THIS
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, fs); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("fee structure created", zap.String("id", fs.FeeStructureID.String()))
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "academics", "create", "fee_structure",
			&fs.FeeStructureID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"name": fs.FeeStructureName, "total_amount": fs.TotalAmount,
			})
	}
	return fs, nil
}

func (s *feeService) GetFeeStructureByID(ctx context.Context, id uuid.UUID) (*models.FeeStructure, error) {
	fs, err := s.repo.GetFeeStructureByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if fs == nil {
		return nil, fmt.Errorf("%w: fee structure %s", ErrNotFound, id)
	}
	return fs, nil
}

func (s *feeService) ListFeeStructures(ctx context.Context, filter repository.FeeStructureFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.FeeStructure, error) {
	return s.repo.ListFeeStructures(ctx, s.pgClient.DB, filter, pagination, sort)
}

func (s *feeService) UpdateFeeStructure(ctx context.Context, req UpdateFeeStructureRequest) (*models.FeeStructure, error) {
	logger := s.logger.With(zap.String("method", "UpdateFeeStructure"), zap.String("id", req.FeeStructureID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	fs, err := s.repo.GetFeeStructureByID(ctx, tx, req.FeeStructureID)
	if err != nil {
		return nil, err
	}
	if fs == nil {
		return nil, fmt.Errorf("%w: fee structure %s", ErrNotFound, req.FeeStructureID)
	}

	old := *fs
	fs.AcademicYearID = req.AcademicYearID
	fs.CourseID = req.CourseID
	fs.SectionID = req.SectionID
	fs.FeeStructureName = req.FeeStructureName
	fs.TotalAmount = req.TotalAmount
	fs.IsActive = req.IsActive
	fs.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateFeeStructure(ctx, tx, fs); err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(map[string]interface{}{"old": old, "new": fs})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fee_structure",
		AggregateID:   fs.FeeStructureID.String(),
		EventType:     string(EventFeeStructureUpdated),
		Topic:         TopicStudent, // <-- ADD THIS
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("fee structure updated")
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "fee_structure",
			&fs.FeeStructureID, "user", req.UpdatedBy, nil, nil, nil)
	}
	return fs, nil
}

func (s *feeService) DeleteFeeStructure(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteFeeStructure"), zap.String("id", id.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	fs, err := s.repo.GetFeeStructureByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if fs == nil {
		return fmt.Errorf("%w: fee structure %s", ErrNotFound, id)
	}

	if err := s.repo.DeleteFeeStructure(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"fee_structure_id": id,
		"deleted_by":       deletedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fee_structure",
		AggregateID:   id.String(),
		EventType:     string(EventFeeStructureDeleted),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("fee structure deleted")
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete", "fee_structure",
			&id, "user", deletedBy, nil, nil, nil)
	}
	return nil
}

// ---------- Fee structure items ----------
func (s *feeService) AddFeeStructureItem(ctx context.Context, feeStructureID uuid.UUID, req CreateFeeStructureItemRequest) (*models.FeeStructureItem, error) {
	logger := s.logger.With(zap.String("method", "AddFeeStructureItem"), zap.String("fee_structure_id", feeStructureID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Verify fee structure exists
	fs, err := s.repo.GetFeeStructureByID(ctx, tx, feeStructureID)
	if err != nil {
		return nil, err
	}
	if fs == nil {
		return nil, fmt.Errorf("%w: fee structure %s", ErrNotFound, feeStructureID)
	}

	item := &models.FeeStructureItem{
		FeeStructureID: feeStructureID,
		FeeHead:        req.FeeHead,
		Amount:         req.Amount,
		IsMandatory:    req.IsMandatory,
		Description:    req.Description,
		CreatedBy:      req.CreatedBy,
	}
	if err := s.repo.AddFeeStructureItem(ctx, tx, item); err != nil {
		return nil, err
	}

	// Update total amount of the fee structure
	fs.TotalAmount += req.Amount
	if err := s.repo.UpdateFeeStructure(ctx, tx, fs); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("fee structure item added")
	return item, nil
}

func (s *feeService) UpdateFeeStructureItem(ctx context.Context, req UpdateFeeStructureItemRequest) error {
	logger := s.logger.With(zap.String("method", "UpdateFeeStructureItem"), zap.String("item_id", req.ItemID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Get the existing item to know old amount and fee structure ID
	items, err := s.repo.GetFeeStructureItems(ctx, tx, req.FeeStructureID)
	if err != nil {
		return err
	}
	var oldItem *models.FeeStructureItem
	for _, it := range items {
		if it.ItemID == req.ItemID {
			oldItem = it
			break
		}
	}
	if oldItem == nil {
		return fmt.Errorf("%w: fee structure item %s", ErrNotFound, req.ItemID)
	}

	oldItem.FeeHead = req.FeeHead
	oldItem.Amount = req.Amount
	oldItem.IsMandatory = req.IsMandatory
	oldItem.Description = req.Description
	if err := s.repo.UpdateFeeStructureItem(ctx, tx, oldItem); err != nil {
		return err
	}

	// Update fee structure total amount (delta)
	delta := req.Amount - oldItem.Amount
	fs, err := s.repo.GetFeeStructureByID(ctx, tx, req.FeeStructureID)
	if err != nil {
		return err
	}
	if fs == nil {
		return fmt.Errorf("%w: fee structure %s", ErrNotFound, req.FeeStructureID)
	}
	fs.TotalAmount += delta
	if err := s.repo.UpdateFeeStructure(ctx, tx, fs); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("fee structure item updated")
	return nil
}

func (s *feeService) DeleteFeeStructureItem(ctx context.Context, itemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteFeeStructureItem"), zap.String("item_id", itemID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Get the item to know fee structure ID and amount
	item, err := s.repo.GetFeeStructureItemByID(ctx, tx, itemID) // Need to implement this in repository
	if err != nil {
		return err
	}
	if item == nil {
		return fmt.Errorf("%w: fee structure item %s", ErrNotFound, itemID)
	}

	// Delete the item
	if err := s.repo.DeleteFeeStructureItem(ctx, tx, itemID); err != nil {
		return err
	}

	// Update total amount of the fee structure
	fs, err := s.repo.GetFeeStructureByID(ctx, tx, item.FeeStructureID)
	if err != nil {
		return err
	}
	if fs == nil {
		return fmt.Errorf("%w: fee structure %s", ErrNotFound, item.FeeStructureID)
	}
	fs.TotalAmount -= item.Amount
	if err := s.repo.UpdateFeeStructure(ctx, tx, fs); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("fee structure item deleted")
	return nil
}

// ---------- Invoices ----------
func (s *feeService) CreateInvoice(ctx context.Context, req CreateInvoiceRequest) (*models.StudentFeeInvoice, error) {
	logger := s.logger.With(zap.String("method", "CreateInvoice"), zap.String("student_id", req.StudentID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	student, err := s.studentRepo.GetByID(ctx, tx, req.StudentID)
	if err != nil || student == nil {
		return nil, fmt.Errorf("%w: student %s", ErrNotFound, req.StudentID)
	}

	fs, err := s.repo.GetFeeStructureByID(ctx, tx, req.FeeStructureID)
	if err != nil || fs == nil {
		return nil, fmt.Errorf("%w: fee structure %s", ErrNotFound, req.FeeStructureID)
	}

	inv := &models.StudentFeeInvoice{
		StudentID:      req.StudentID,
		FeeStructureID: req.FeeStructureID,
		InvoiceNo:      req.InvoiceNo,
		DueDate:        req.DueDate,
		TotalAmount:    req.TotalAmount,
		PaidAmount:     0,
		Balance:        req.TotalAmount,
		Status:         "unpaid", // FIXED: was "pending", now matches DB constraint
		CreatedBy:      req.CreatedBy,
	}

	items := make([]*models.StudentFeeInvoiceItem, 0, len(req.Items))
	for _, it := range req.Items {
		items = append(items, &models.StudentFeeInvoiceItem{
			FeeHead:     it.FeeHead,
			Amount:      it.Amount,
			IsMandatory: it.IsMandatory,
			CreatedBy:   req.CreatedBy,
		})
	}

	if err := s.repo.CreateInvoice(ctx, tx, inv, items); err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(inv)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fee_invoice",
		AggregateID:   inv.InvoiceID.String(),
		EventType:     string(EventFeeInvoiceCreated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("invoice created", zap.String("invoice_id", inv.InvoiceID.String()))

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "create", "fee_invoice",
			&inv.InvoiceID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"invoice_no": inv.InvoiceNo, "total_amount": inv.TotalAmount,
			})
	}

	title := "New Fee Invoice"
	message := fmt.Sprintf("A new fee invoice %s of amount %.2f has been generated. Due date: %s.", inv.InvoiceNo, inv.TotalAmount, inv.DueDate.Format("2006-01-02"))
	s.sendNotificationToStudent(ctx, req.StudentID, title, message, models.NotificationTypeInfo, models.PriorityNormal, req.CreatedBy)

	return inv, nil
}

func (s *feeService) GetInvoiceByID(ctx context.Context, id uuid.UUID) (*models.StudentFeeInvoice, error) {
	inv, err := s.repo.GetInvoiceByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return nil, fmt.Errorf("%w: invoice %s", ErrNotFound, id)
	}
	return inv, nil
}

func (s *feeService) GetInvoiceByNumber(ctx context.Context, invoiceNo string) (*models.StudentFeeInvoice, error) {
	inv, err := s.repo.GetInvoiceByNumber(ctx, s.pgClient.DB, invoiceNo)
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return nil, fmt.Errorf("%w: invoice %s", ErrNotFound, invoiceNo)
	}
	return inv, nil
}

func (s *feeService) ListInvoices(ctx context.Context, filter repository.InvoiceFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.StudentFeeInvoice, error) {
	return s.repo.ListInvoices(ctx, s.pgClient.DB, filter, pagination, sort)
}

func (s *feeService) UpdateInvoiceStatus(ctx context.Context, id uuid.UUID, status string, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UpdateInvoiceStatus"), zap.String("invoice_id", id.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	inv, err := s.repo.GetInvoiceByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if inv == nil {
		return fmt.Errorf("%w: invoice %s", ErrNotFound, id)
	}

	if err := s.repo.UpdateInvoiceStatus(ctx, tx, id, status, updatedBy); err != nil {
		return err
	}

	// Outbox event
	payload, _ := json.Marshal(map[string]interface{}{
		"invoice_id": id,
		"status":     status,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fee_invoice",
		AggregateID:   id.String(),
		EventType:     string(EventFeeInvoiceUpdated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("invoice status updated")
	return nil
}

// ---------- Payments ----------
func (s *feeService) CreatePayment(ctx context.Context, req CreatePaymentRequest) (*models.StudentFeePayment, error) {
	logger := s.logger.With(zap.String("method", "CreatePayment"), zap.String("invoice_id", req.InvoiceID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	inv, err := s.repo.GetInvoiceByID(ctx, tx, req.InvoiceID)
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return nil, fmt.Errorf("%w: invoice %s", ErrNotFound, req.InvoiceID)
	}

	payment := &models.StudentFeePayment{
		InvoiceID:     req.InvoiceID,
		PaymentDate:   req.PaymentDate,
		Amount:        req.Amount,
		PaymentMode:   req.PaymentMode,
		TransactionID: req.TransactionID,
		ReceiptNo:     req.ReceiptNo,
		Remarks:       req.Remarks,
		CreatedBy:     req.CreatedBy,
	}
	if err := s.repo.CreatePayment(ctx, tx, payment); err != nil {
		return nil, err
	}

	// Update invoice paid amount and balance
	newPaidAmount := inv.PaidAmount + req.Amount
	if err := s.repo.UpdateInvoicePaidAmount(ctx, tx, inv.InvoiceID, newPaidAmount); err != nil {
		return nil, err
	}
	// Update invoice status if fully paid
	if newPaidAmount >= inv.TotalAmount {
		if err := s.repo.UpdateInvoiceStatus(ctx, tx, inv.InvoiceID, "paid", req.CreatedBy); err != nil {
			return nil, err
		}
	}

	// Outbox event
	payload, _ := json.Marshal(payment)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fee_payment",
		AggregateID:   payment.PaymentID.String(),
		EventType:     string(EventFeePaymentCreated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("payment created", zap.String("payment_id", payment.PaymentID.String()))
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &inv.StudentID, "academics", "create", "fee_payment",
			&payment.PaymentID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"amount": payment.Amount, "invoice_id": req.InvoiceID.String(),
			})
	}

	// Send notification to student
	title := "Fee Payment Received"
	message := fmt.Sprintf("A payment of %.2f has been received for invoice %s.", payment.Amount, inv.InvoiceNo)
	s.sendNotificationToStudent(ctx, inv.StudentID, title, message, models.NotificationTypeInfo, models.PriorityNormal, req.CreatedBy)

	return payment, nil
}

func (s *feeService) GetPaymentByID(ctx context.Context, id uuid.UUID) (*models.StudentFeePayment, error) {
	payment, err := s.repo.GetPaymentByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if payment == nil {
		return nil, fmt.Errorf("%w: payment %s", ErrNotFound, id)
	}
	return payment, nil
}

func (s *feeService) GetPaymentsByInvoice(ctx context.Context, invoiceID uuid.UUID) ([]*models.StudentFeePayment, error) {
	return s.repo.GetPaymentsByInvoice(ctx, s.pgClient.DB, invoiceID)
}

func (s *feeService) ListPayments(ctx context.Context, filter repository.PaymentFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.StudentFeePayment, error) {
	return s.repo.ListPayments(ctx, s.pgClient.DB, filter, pagination, sort)
}

// ---------- Discounts ----------
func (s *feeService) CreateDiscount(ctx context.Context, req CreateDiscountRequest) (*models.FeeDiscount, error) {
	logger := s.logger.With(zap.String("method", "CreateDiscount"), zap.String("student_id", req.StudentID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	discount := &models.FeeDiscount{
		StudentID:     req.StudentID,
		DiscountType:  req.DiscountType,
		DiscountValue: req.DiscountValue,
		Reason:        req.Reason,
		ApprovedBy:    req.ApprovedBy,
		ValidFrom:     req.ValidFrom,
		ValidUntil:    req.ValidUntil,
		CreatedBy:     req.CreatedBy,
	}
	if err := s.repo.CreateDiscount(ctx, tx, discount); err != nil {
		return nil, err
	}

	// Outbox event
	payload, _ := json.Marshal(discount)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fee_discount",
		AggregateID:   discount.DiscountID.String(),
		EventType:     string(EventFeeDiscountCreated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("discount created", zap.String("discount_id", discount.DiscountID.String()))

	// Send notification to student
	title := "Fee Discount Applied"
	message := fmt.Sprintf("A discount of %.2f (%s) has been applied to your fee account. Reason: %s.", discount.DiscountValue, discount.DiscountType, discount.Reason)
	s.sendNotificationToStudent(ctx, req.StudentID, title, message, models.NotificationTypeInfo, models.PriorityNormal, req.CreatedBy)

	return discount, nil
}

func (s *feeService) UpdateDiscount(ctx context.Context, req UpdateDiscountRequest) (*models.FeeDiscount, error) {
	logger := s.logger.With(zap.String("method", "UpdateDiscount"), zap.String("discount_id", req.DiscountID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	discount, err := s.repo.GetDiscountByID(ctx, tx, req.DiscountID)
	if err != nil {
		return nil, err
	}
	if discount == nil {
		return nil, fmt.Errorf("%w: discount %s", ErrNotFound, req.DiscountID)
	}

	discount.DiscountType = req.DiscountType
	discount.DiscountValue = req.DiscountValue
	discount.Reason = req.Reason
	discount.ApprovedBy = req.ApprovedBy
	discount.ValidFrom = req.ValidFrom
	discount.ValidUntil = req.ValidUntil

	if err := s.repo.UpdateDiscount(ctx, tx, discount); err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(discount)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fee_discount",
		AggregateID:   discount.DiscountID.String(),
		EventType:     string(EventFeeDiscountUpdated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("discount updated")
	return discount, nil
}

func (s *feeService) DeleteDiscount(ctx context.Context, id uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteDiscount"), zap.String("discount_id", id.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteDiscount(ctx, tx, id); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("discount deleted")
	return nil
}

// ---------- Penalties ----------
func (s *feeService) CreatePenalty(ctx context.Context, req CreatePenaltyRequest) (*models.FeePenalty, error) {
	logger := s.logger.With(zap.String("method", "CreatePenalty"), zap.String("invoice_id", req.InvoiceID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Get invoice to know student ID for notification
	inv, err := s.repo.GetInvoiceByID(ctx, tx, req.InvoiceID)
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return nil, fmt.Errorf("%w: invoice %s", ErrNotFound, req.InvoiceID)
	}

	penalty := &models.FeePenalty{
		InvoiceID:   req.InvoiceID,
		PenaltyDate: req.PenaltyDate,
		Amount:      req.Amount,
		Reason:      req.Reason,
		Waived:      req.Waived,
		WaivedBy:    req.WaivedBy,
		CreatedBy:   req.CreatedBy,
	}
	if err := s.repo.CreatePenalty(ctx, tx, penalty); err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(penalty)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fee_penalty",
		AggregateID:   penalty.PenaltyID.String(),
		EventType:     string(EventFeePenaltyCreated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("penalty created")

	// Send notification to student
	title := "Fee Penalty Added"
	message := fmt.Sprintf("A penalty of %.2f has been added to invoice %s due to: %s.", penalty.Amount, inv.InvoiceNo, penalty.Reason)
	s.sendNotificationToStudent(ctx, inv.StudentID, title, message, models.NotificationTypeWarning, models.PriorityHigh, req.CreatedBy)

	return penalty, nil
}

func (s *feeService) UpdatePenalty(ctx context.Context, req UpdatePenaltyRequest) (*models.FeePenalty, error) {
	logger := s.logger.With(zap.String("method", "UpdatePenalty"), zap.String("penalty_id", req.PenaltyID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Need repository method GetPenaltyByID
	penalty, err := s.repo.GetPenaltyByID(ctx, tx, req.PenaltyID)
	if err != nil {
		return nil, err
	}
	if penalty == nil {
		return nil, fmt.Errorf("%w: penalty %s", ErrNotFound, req.PenaltyID)
	}

	penalty.PenaltyDate = req.PenaltyDate
	penalty.Amount = req.Amount
	penalty.Reason = req.Reason
	penalty.Waived = req.Waived
	penalty.WaivedBy = req.WaivedBy

	if err := s.repo.UpdatePenalty(ctx, tx, penalty); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("penalty updated")
	return penalty, nil
}

// ---------- Receipts ----------
// func (s *feeService) GenerateReceipt(ctx context.Context, paymentID uuid.UUID, receiptNo string) (*models.FeeReceipt, error) {
// 	logger := s.logger.With(zap.String("method", "GenerateReceipt"), zap.String("payment_id", paymentID.String()))
// 	tx, err := s.pgClient.BeginTx(ctx, nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("begin tx: %w", err)
// 	}
// 	defer tx.Rollback()

// 	payment, err := s.repo.GetPaymentByID(ctx, tx, paymentID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if payment == nil {
// 		return nil, fmt.Errorf("%w: payment %s", ErrNotFound, paymentID)
// 	}

// 	// Get invoice to know student ID
// 	inv, err := s.repo.GetInvoiceByID(ctx, tx, payment.InvoiceID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if inv == nil {
// 		return nil, fmt.Errorf("%w: invoice %s", ErrNotFound, payment.InvoiceID)
// 	}

// 	receipt := &models.FeeReceipt{
// 		PaymentID:   paymentID,
// 		ReceiptNo:   receiptNo,
// 		ReceiptData: map[string]interface{}{"payment": payment},
// 		CreatedBy:   payment.CreatedBy,
// 	}
// 	if err := s.repo.CreateReceipt(ctx, tx, receipt); err != nil {
// 		return nil, err
// 	}

// 	payload, _ := json.Marshal(receipt)
// 	outboxEvent := &outbox.Event{
// 		EventID:       uuid.New().String(),
// 		AggregateType: "fee_receipt",
// 		AggregateID:   receipt.ReceiptID.String(),
// 		EventType:     string(EventFeeReceiptGenerated),
// 		Payload:       payload,
// 		Status:        "pending",
// 	}
// 	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
// 		return nil, fmt.Errorf("store outbox event: %w", err)
// 	}

// 	if err := tx.Commit(); err != nil {
// 		return nil, fmt.Errorf("commit tx: %w", err)
// 	}

// 	logger.Info("receipt generated", zap.String("receipt_id", receipt.ReceiptID.String()))

// 	// Send notification to student
// 	title := "Fee Receipt Generated"
// 	message := fmt.Sprintf("Receipt %s has been generated for payment of %.2f on invoice %s.", receipt.ReceiptNo, payment.Amount, inv.InvoiceNo)
// 	s.sendNotificationToStudent(ctx, inv.StudentID, title, message, models.NotificationTypeInfo, models.PriorityNormal, payment.CreatedBy)

// 	return receipt, nil
// }

func (s *feeService) GetReceiptByNumber(ctx context.Context, receiptNo string) (*models.FeeReceipt, error) {
	return s.repo.GetReceiptByNumber(ctx, s.pgClient.DB, receiptNo)
}

// ---------- Validation helpers ----------
func (s *feeService) validateFeeStructureInput(req CreateFeeStructureRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if req.AcademicYearID == uuid.Nil {
		return fmt.Errorf("%w: academic_year_id is required", ErrInvalidInput)
	}
	if req.CourseID == uuid.Nil {
		return fmt.Errorf("%w: course_id is required", ErrInvalidInput)
	}
	if strings.TrimSpace(req.FeeStructureName) == "" {
		return fmt.Errorf("%w: fee_structure_name is required", ErrInvalidInput)
	}
	if req.TotalAmount < 0 {
		return fmt.Errorf("%w: total_amount cannot be negative", ErrInvalidInput)
	}
	return nil
}

func (s *feeService) validateFeeStructureReferences(ctx context.Context, tx *sql.Tx, req CreateFeeStructureRequest) error {
	// Check academic year
	ay, err := s.academicYearRepo.GetByID(ctx, tx, req.AcademicYearID)
	if err != nil || ay == nil {
		return fmt.Errorf("%w: academic year %s", ErrNotFound, req.AcademicYearID)
	}
	// Check course
	course, err := s.courseRepo.GetByID(ctx, tx, req.CourseID)
	if err != nil || course == nil {
		return fmt.Errorf("%w: course %s", ErrNotFound, req.CourseID)
	}
	if req.SectionID != nil {
		// Optionally verify section belongs to the course
		// This would require a section repo method.
	}
	return nil
}
func (s *feeService) GenerateReceipt(ctx context.Context, paymentID uuid.UUID, receiptNo string, idempotencyKey string) (*models.FeeReceipt, error) {
	logger := s.logger.With(zap.String("method", "GenerateReceipt"), zap.String("payment_id", paymentID.String()))

	// Idempotency check
	if idempotencyKey != "" {
		var existing *models.FeeReceipt
		if err := s.idempotencyStore.Get(ctx, nil, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check if receipt already exists for this payment
	existingReceipt, _ := s.repo.GetReceiptByPaymentID(ctx, tx, paymentID)
	if existingReceipt != nil {
		logger.Info("receipt already exists for this payment")
		return existingReceipt, nil
	}

	// Check if receipt number already exists (to avoid duplicate key violation)
	if receiptNo != "" {
		existingByNo, _ := s.repo.GetReceiptByNumber(ctx, tx, receiptNo)
		if existingByNo != nil {
			return nil, fmt.Errorf("receipt number %s already exists", receiptNo)
		}
	} else {
		// Auto-generate receipt number if not provided
		receiptNo = generateReceiptNumber() // implement helper
	}

	payment, err := s.repo.GetPaymentByID(ctx, tx, paymentID)
	if err != nil {
		return nil, err
	}
	if payment == nil {
		return nil, fmt.Errorf("%w: payment %s", ErrNotFound, paymentID)
	}

	inv, err := s.repo.GetInvoiceByID(ctx, tx, payment.InvoiceID)
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return nil, fmt.Errorf("%w: invoice %s", ErrNotFound, payment.InvoiceID)
	}

	receipt := &models.FeeReceipt{
		PaymentID:   paymentID,
		ReceiptNo:   receiptNo,
		ReceiptData: map[string]interface{}{"payment": payment, "invoice": inv},
		CreatedBy:   payment.CreatedBy,
	}

	if err := s.repo.CreateReceipt(ctx, tx, receipt); err != nil {
		return nil, err
	}

	// Store idempotency response
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, receipt); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	payload, _ := json.Marshal(receipt)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fee_receipt",
		AggregateID:   receipt.ReceiptID.String(),
		EventType:     string(EventFeeReceiptGenerated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("receipt generated", zap.String("receipt_id", receipt.ReceiptID.String()))

	title := "Fee Receipt Generated"
	message := fmt.Sprintf("Receipt %s has been generated for payment of %.2f on invoice %s.", receipt.ReceiptNo, payment.Amount, inv.InvoiceNo)
	s.sendNotificationToStudent(ctx, inv.StudentID, title, message, models.NotificationTypeInfo, models.PriorityNormal, payment.CreatedBy)

	return receipt, nil
}

// Helper to generate unique receipt number
func generateReceiptNumber() string {
	return fmt.Sprintf("RCPT-%d", time.Now().UnixNano())
}

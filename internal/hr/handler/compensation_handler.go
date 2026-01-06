package handler

import (
	"auth-service/internal/hr/models/compensation"
	"auth-service/internal/hr/service"
	"auth-service/internal/util"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
)

// CompensationHandler handles HTTP requests for compensation operations
type CompensationHandler struct {
	compService      service.CompensationService
	compQueryService service.CompensationQueryService
	logger           *zap.Logger
}

// NewCompensationHandler creates a new compensation handler
func NewCompensationHandler(
	compService service.CompensationService,
	compQueryService service.CompensationQueryService,
	logger *zap.Logger,
) *CompensationHandler {
	return &CompensationHandler{
		compService:      compService,
		compQueryService: compQueryService,
		logger:           logger,
	}
}

// ============================================================================
// PAY UNIT HANDLERS
// ============================================================================

// GetPayUnitByIDHandler retrieves a pay unit by ID
func (h *CompensationHandler) GetPayUnitByIDHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	payUnitIDStr := chi.URLParam(r, "payUnitID")

	payUnitID, err := uuid.Parse(payUnitIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid pay unit ID")
		return
	}

	payUnit, err := h.compQueryService.GetPayUnitByID(ctx, payUnitID)
	if err != nil {
		h.logger.Error("Failed to get pay unit",
			util.String("pay_unit_id", payUnitID.String()),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusNotFound, "Pay unit not found")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"pay_unit": payUnit,
	})
}

// ListPayUnitsHandler lists all pay units
func (h *CompensationHandler) ListPayUnitsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	payUnits, err := h.compQueryService.ListPayUnits(ctx)
	if err != nil {
		h.logger.Error("Failed to list pay units", util.ErrorField(err))
		util.RespondWithError(w, http.StatusInternalServerError, "Failed to list pay units")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"pay_units": payUnits,
		"count":     len(payUnits),
	})
}

// CreatePayUnitHandler creates a new pay unit
func (h *CompensationHandler) CreatePayUnitHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get actor info from context
	actorIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		util.RespondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	actorID, err := uuid.Parse(actorIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	actorType, _ := ctx.Value("session_type").(string)
	if actorType == "" {
		actorType = "admin" // default
	}

	var req struct {
		Name        string  `json:"name" validate:"required,min=1,max=30"`
		Description *string `json:"description,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" {
		util.RespondWithError(w, http.StatusBadRequest, "Name is required")
		return
	}

	payUnit := &compensation.PayUnit{
		PayUnitID:   uuid.New(),
		Name:        req.Name,
		Description: req.Description,
	}

	createdPayUnit, err := h.compService.CreatePayUnit(ctx, payUnit, actorType, actorID)
	if err != nil {
		h.logger.Error("Failed to create pay unit",
			util.String("name", req.Name),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusInternalServerError, "Failed to create pay unit")
		return
	}

	util.RespondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success":  true,
		"pay_unit": createdPayUnit,
		"message":  "Pay unit created successfully",
	})
}

// ============================================================================
// COMPENSATION STRUCTURE HANDLERS
// ============================================================================

// GetCompensationStructureByIDHandler retrieves a compensation structure by ID
func (h *CompensationHandler) GetCompensationStructureByIDHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	structureIDStr := chi.URLParam(r, "structureID")

	structureID, err := uuid.Parse(structureIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid structure ID")
		return
	}

	structure, err := h.compQueryService.GetCompensationStructureByID(ctx, structureID)
	if err != nil {
		h.logger.Error("Failed to get compensation structure",
			util.String("structure_id", structureID.String()),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusNotFound, "Compensation structure not found")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":                true,
		"compensation_structure": structure,
	})
}

// GetCompensationStructuresByCompanyHandler retrieves compensation structures for a company
func (h *CompensationHandler) GetCompensationStructuresByCompanyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get query parameters
	activeOnly := r.URL.Query().Get("active_only") == "true"
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	} else if pageSize > 100 {
		pageSize = 100
	}

	structures, totalCount, err := h.compQueryService.GetCompensationStructuresByCompany(
		ctx, companyID, activeOnly, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to get compensation structures",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusInternalServerError, "Failed to get compensation structures")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":                 true,
		"compensation_structures": structures,
		"pagination": map[string]interface{}{
			"page":        page,
			"page_size":   pageSize,
			"total":       totalCount,
			"total_pages": (totalCount + pageSize - 1) / pageSize,
		},
	})
}

// GetCompensationStructureByCodeHandler retrieves a compensation structure by code
func (h *CompensationHandler) GetCompensationStructureByCodeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	structureCode := chi.URLParam(r, "structureCode")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	if structureCode == "" {
		util.RespondWithError(w, http.StatusBadRequest, "Structure code is required")
		return
	}

	structure, err := h.compQueryService.GetCompensationStructureByCode(ctx, companyID, structureCode)
	if err != nil {
		h.logger.Error("Failed to get compensation structure by code",
			util.String("company_id", companyID.String()),
			util.String("structure_code", structureCode),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusNotFound, "Compensation structure not found")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":                true,
		"compensation_structure": structure,
	})
}

// CreateCompensationStructureHandler creates a new compensation structure
func (h *CompensationHandler) CreateCompensationStructureHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get actor info from context
	actorIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		util.RespondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	actorID, err := uuid.Parse(actorIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	actorType, _ := ctx.Value("session_type").(string)
	if actorType == "" {
		actorType = "admin"
	}

	var req struct {
		StructureCode string                   `json:"structure_code" validate:"required,min=1,max=50"`
		Name          string                   `json:"name" validate:"required,min=1,max=100"`
		Currency      string                   `json:"currency" validate:"required"`
		Components    []compensation.Component `json:"components" validate:"required,min=1"`
		IsActive      *bool                    `json:"is_active,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.StructureCode == "" || req.Name == "" || req.Currency == "" || len(req.Components) == 0 {
		util.RespondWithError(w, http.StatusBadRequest, "Structure code, name, currency, and components are required")
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	structure := &compensation.CompensationStructure{
		StructureID:   uuid.New(),
		CompanyID:     companyID,
		StructureCode: req.StructureCode,
		Name:          req.Name,
		Currency:      req.Currency,
		Components:    req.Components,
		IsActive:      isActive,
		CreatedAt:     time.Now().UTC(),
	}

	createdStructure, err := h.compService.CreateCompensationStructure(ctx, structure, actorType, actorID, nil)
	if err != nil {
		h.logger.Error("Failed to create compensation structure",
			util.String("company_id", companyID.String()),
			util.String("structure_code", req.StructureCode),
			util.ErrorField(err))

		// Check for duplicate structure code
		if err.Error() == fmt.Sprintf("compensation structure with code '%s' already exists", req.StructureCode) {
			util.RespondWithError(w, http.StatusConflict, err.Error())
		} else {
			util.RespondWithError(w, http.StatusInternalServerError, "Failed to create compensation structure")
		}
		return
	}

	util.RespondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success":                true,
		"compensation_structure": createdStructure,
		"message":                "Compensation structure created successfully",
	})
}

// UpdateCompensationStructureHandler updates a compensation structure
func (h *CompensationHandler) UpdateCompensationStructureHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	structureIDStr := chi.URLParam(r, "structureID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	structureID, err := uuid.Parse(structureIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid structure ID")
		return
	}

	// Get actor info from context
	actorIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		util.RespondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	actorID, err := uuid.Parse(actorIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	actorType, _ := ctx.Value("session_type").(string)
	if actorType == "" {
		actorType = "admin"
	}

	var req struct {
		StructureCode string                   `json:"structure_code" validate:"required,min=1,max=50"`
		Name          string                   `json:"name" validate:"required,min=1,max=100"`
		Currency      string                   `json:"currency" validate:"required"`
		Components    []compensation.Component `json:"components" validate:"required,min=1"`
		IsActive      bool                     `json:"is_active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	structure := &compensation.CompensationStructure{
		StructureID:   structureID,
		CompanyID:     companyID,
		StructureCode: req.StructureCode,
		Name:          req.Name,
		Currency:      req.Currency,
		Components:    req.Components,
		IsActive:      req.IsActive,
	}

	err = h.compService.UpdateCompensationStructure(ctx, structure, actorType, actorID, nil)
	if err != nil {
		h.logger.Error("Failed to update compensation structure",
			util.String("structure_id", structureID.String()),
			util.ErrorField(err))

		if err.Error() == "compensation structure not found" {
			util.RespondWithError(w, http.StatusNotFound, err.Error())
		} else if err.Error() == "cannot change company ID for compensation structure" {
			util.RespondWithError(w, http.StatusBadRequest, err.Error())
		} else if err.Error() == fmt.Sprintf("compensation structure with code '%s' already exists", req.StructureCode) {
			util.RespondWithError(w, http.StatusConflict, err.Error())
		} else {
			util.RespondWithError(w, http.StatusInternalServerError, "Failed to update compensation structure")
		}
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Compensation structure updated successfully",
	})
}

// DeactivateCompensationStructureHandler deactivates a compensation structure
func (h *CompensationHandler) DeactivateCompensationStructureHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	structureIDStr := chi.URLParam(r, "structureID")

	structureID, err := uuid.Parse(structureIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid structure ID")
		return
	}

	// Get actor info from context
	actorIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		util.RespondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	actorID, err := uuid.Parse(actorIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	actorType, _ := ctx.Value("session_type").(string)
	if actorType == "" {
		actorType = "admin"
	}

	err = h.compService.DeactivateCompensationStructure(ctx, structureID, actorType, actorID, nil)
	if err != nil {
		h.logger.Error("Failed to deactivate compensation structure",
			util.String("structure_id", structureID.String()),
			util.ErrorField(err))

		if err.Error() == "compensation structure not found" {
			util.RespondWithError(w, http.StatusNotFound, err.Error())
		} else if err.Error() == "compensation structure is already inactive" {
			util.RespondWithError(w, http.StatusBadRequest, err.Error())
		} else if err.Error() == "cannot deactivate structure that is in use by active employees" {
			util.RespondWithError(w, http.StatusConflict, err.Error())
		} else {
			util.RespondWithError(w, http.StatusInternalServerError, "Failed to deactivate compensation structure")
		}
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Compensation structure deactivated successfully",
	})
}

// ============================================================================
// USER COMPENSATION HANDLERS
// ============================================================================

// GetUserCompensationsByUserHandler retrieves compensations for a user
func (h *CompensationHandler) GetUserCompensationsByUserHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	comps, err := h.compQueryService.GetUserCompensationsByUser(ctx, userID)
	if err != nil {
		h.logger.Error("Failed to get user compensations",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusInternalServerError, "Failed to get user compensations")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":            true,
		"user_compensations": comps,
		"count":              len(comps),
	})
}

// GetCurrentUserCompensationHandler retrieves current compensation for a user
func (h *CompensationHandler) GetCurrentUserCompensationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	comp, err := h.compQueryService.GetCurrentUserCompensation(ctx, userID)
	if err != nil {
		h.logger.Error("Failed to get current user compensation",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusNotFound, "No active compensation found for user")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":           true,
		"user_compensation": comp,
	})
}

// GetUserCompensationsByCompanyHandler retrieves compensations for a company
func (h *CompensationHandler) GetUserCompensationsByCompanyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	} else if pageSize > 100 {
		pageSize = 100
	}

	comps, totalCount, err := h.compQueryService.GetUserCompensationsByCompany(ctx, companyID, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to get user compensations by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusInternalServerError, "Failed to get user compensations")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":            true,
		"user_compensations": comps,
		"pagination": map[string]interface{}{
			"page":        page,
			"page_size":   pageSize,
			"total":       totalCount,
			"total_pages": (totalCount + pageSize - 1) / pageSize,
		},
	})
}

// CreateUserCompensationHandler creates a new user compensation
func (h *CompensationHandler) CreateUserCompensationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")

	_, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get actor info from context
	actorIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		util.RespondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	actorID, err := uuid.Parse(actorIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	actorType, _ := ctx.Value("session_type").(string)
	if actorType == "" {
		actorType = "admin"
	}

	var req struct {
		UserID        uuid.UUID  `json:"user_id" validate:"required"`
		StructureID   uuid.UUID  `json:"structure_id" validate:"required"`
		PayUnitID     *uuid.UUID `json:"pay_unit_id,omitempty"`
		CTCAmount     string     `json:"ctc_amount" validate:"required"`
		EffectiveFrom string     `json:"effective_from" validate:"required"`
		EffectiveTo   *string    `json:"effective_to,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Parse CTC amount
	ctcAmount, err := decimal.NewFromString(req.CTCAmount)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid CTC amount")
		return
	}

	// Parse effective from date
	effectiveFrom, err := time.Parse(time.RFC3339, req.EffectiveFrom)
	if err != nil {
		effectiveFrom, err = time.Parse("2006-01-02", req.EffectiveFrom)
		if err != nil {
			util.RespondWithError(w, http.StatusBadRequest, "Invalid effective_from date format. Use RFC3339 or YYYY-MM-DD")
			return
		}
	}

	// Parse effective to date if provided
	var effectiveToPtr *time.Time
	if req.EffectiveTo != nil {
		effectiveTo, err := time.Parse(time.RFC3339, *req.EffectiveTo)
		if err != nil {
			effectiveTo, err = time.Parse("2006-01-02", *req.EffectiveTo)
			if err != nil {
				util.RespondWithError(w, http.StatusBadRequest, "Invalid effective_to date format. Use RFC3339 or YYYY-MM-DD")
				return
			}
		}
		effectiveToPtr = &effectiveTo
	}

	userComp := &compensation.UserCompensation{
		UserID:        req.UserID,
		StructureID:   req.StructureID,
		PayUnitID:     req.PayUnitID,
		CTCAmount:     ctcAmount,
		EffectiveFrom: effectiveFrom,
		EffectiveTo:   effectiveToPtr,
		AssignedBy:    &actorID,
		CreatedAt:     time.Now().UTC(),
	}

	createdComp, err := h.compService.CreateUserCompensation(ctx, userComp, actorType, actorID, nil)
	if err != nil {
		h.logger.Error("Failed to create user compensation",
			util.String("user_id", req.UserID.String()),
			util.String("structure_id", req.StructureID.String()),
			util.ErrorField(err))

		if err.Error() == "compensation structure not found" {
			util.RespondWithError(w, http.StatusNotFound, err.Error())
		} else if err.Error() == "cannot assign inactive compensation structure" {
			util.RespondWithError(w, http.StatusBadRequest, err.Error())
		} else {
			util.RespondWithError(w, http.StatusInternalServerError, "Failed to create user compensation")
		}
		return
	}

	util.RespondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success":           true,
		"user_compensation": createdComp,
		"message":           "User compensation created successfully",
	})
}

// UpdateUserCompensationHandler updates a user compensation
func (h *CompensationHandler) UpdateUserCompensationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	userIDStr := chi.URLParam(r, "userID")

	_, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Get actor info from context
	actorIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		util.RespondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	actorID, err := uuid.Parse(actorIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	actorType, _ := ctx.Value("session_type").(string)
	if actorType == "" {
		actorType = "admin"
	}

	var req struct {
		StructureID   uuid.UUID  `json:"structure_id" validate:"required"`
		EffectiveFrom string     `json:"effective_from" validate:"required"`
		PayUnitID     *uuid.UUID `json:"pay_unit_id,omitempty"`
		CTCAmount     string     `json:"ctc_amount"`
		EffectiveTo   *string    `json:"effective_to,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Parse effective from date
	effectiveFrom, err := time.Parse(time.RFC3339, req.EffectiveFrom)
	if err != nil {
		effectiveFrom, err = time.Parse("2006-01-02", req.EffectiveFrom)
		if err != nil {
			util.RespondWithError(w, http.StatusBadRequest, "Invalid effective_from date format. Use RFC3339 or YYYY-MM-DD")
			return
		}
	}

	// Parse effective to date if provided
	var effectiveToPtr *time.Time
	if req.EffectiveTo != nil {
		effectiveTo, err := time.Parse(time.RFC3339, *req.EffectiveTo)
		if err != nil {
			effectiveTo, err = time.Parse("2006-01-02", *req.EffectiveTo)
			if err != nil {
				util.RespondWithError(w, http.StatusBadRequest, "Invalid effective_to date format. Use RFC3339 or YYYY-MM-DD")
				return
			}
		}
		effectiveToPtr = &effectiveTo
	}

	// Parse CTC amount if provided
	var ctcAmount decimal.Decimal
	if req.CTCAmount != "" {
		ctcAmount, err = decimal.NewFromString(req.CTCAmount)
		if err != nil {
			util.RespondWithError(w, http.StatusBadRequest, "Invalid CTC amount")
			return
		}
	}

	userComp := &compensation.UserCompensation{
		UserID:        userID,
		StructureID:   req.StructureID,
		PayUnitID:     req.PayUnitID,
		CTCAmount:     ctcAmount,
		EffectiveFrom: effectiveFrom,
		EffectiveTo:   effectiveToPtr,
		AssignedBy:    &actorID,
	}

	err = h.compService.UpdateUserCompensation(ctx, userComp, actorType, actorID, nil)
	if err != nil {
		h.logger.Error("Failed to update user compensation",
			util.String("user_id", userID.String()),
			util.String("structure_id", req.StructureID.String()),
			util.ErrorField(err))

		if err.Error() == "user compensation not found" {
			util.RespondWithError(w, http.StatusNotFound, err.Error())
		} else if err.Error() == "cannot change user ID or structure ID for user compensation" {
			util.RespondWithError(w, http.StatusBadRequest, err.Error())
		} else if err.Error() == "compensation structure not found" {
			util.RespondWithError(w, http.StatusNotFound, err.Error())
		} else {
			util.RespondWithError(w, http.StatusInternalServerError, "Failed to update user compensation")
		}
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "User compensation updated successfully",
	})
}

// EndUserCompensationHandler ends a user's compensation
func (h *CompensationHandler) EndUserCompensationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Get actor info from context
	actorIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		util.RespondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	actorID, err := uuid.Parse(actorIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	actorType, _ := ctx.Value("session_type").(string)
	if actorType == "" {
		actorType = "admin"
	}

	var req struct {
		EndDate string `json:"end_date,omitempty"`
	}

	var endDate time.Time
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.EndDate != "" {
		endDate, err = time.Parse(time.RFC3339, req.EndDate)
		if err != nil {
			endDate, err = time.Parse("2006-01-02", req.EndDate)
			if err != nil {
				util.RespondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use RFC3339 or YYYY-MM-DD")
				return
			}
		}
	} else {
		endDate = time.Now().UTC()
	}

	err = h.compService.EndUserCompensation(ctx, userID, endDate, actorType, actorID, nil)
	if err != nil {
		h.logger.Error("Failed to end user compensation",
			util.String("user_id", userID.String()),
			util.ErrorField(err))

		if err.Error() == "no active compensation found for user" {
			util.RespondWithError(w, http.StatusNotFound, err.Error())
		} else {
			util.RespondWithError(w, http.StatusInternalServerError, "Failed to end user compensation")
		}
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"message":  "User compensation ended successfully",
		"end_date": endDate.Format(time.RFC3339),
	})
}

// ============================================================================
// ANALYTICS AND REPORT HANDLERS
// ============================================================================

// GetCompensationStatsByCompanyHandler gets compensation statistics for a company
func (h *CompensationHandler) GetCompensationStatsByCompanyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	stats, err := h.compQueryService.GetCompensationStatsByCompany(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to get compensation stats",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusInternalServerError, "Failed to get compensation statistics")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"stats":   stats,
	})
}

// GetAverageCTCByDepartmentHandler gets average CTC by department
func (h *CompensationHandler) GetAverageCTCByDepartmentHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	averages, err := h.compQueryService.GetAverageCTCByDepartment(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to get average CTC by department",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusInternalServerError, "Failed to get average CTC by department")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"averages": averages,
		"count":    len(averages),
	})
}

// GenerateCompensationReportHandler generates a compensation report
func (h *CompensationHandler) GenerateCompensationReportHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get query parameters
	reportType := r.URL.Query().Get("report_type")
	if reportType == "" {
		reportType = "salary_summary"
	}

	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	// Default to last 30 days if not provided
	var startDate, endDate time.Time
	if startDateStr == "" || endDateStr == "" {
		endDate = time.Now().UTC()
		startDate = endDate.AddDate(0, -1, 0) // Last 30 days
	} else {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			util.RespondWithError(w, http.StatusBadRequest, "Invalid start_date format. Use YYYY-MM-DD")
			return
		}

		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			util.RespondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use YYYY-MM-DD")
			return
		}
	}

	data, contentType, err := h.compQueryService.GenerateCompensationReport(ctx, companyID, reportType, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to generate compensation report",
			util.String("company_id", companyID.String()),
			util.String("report_type", reportType),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusInternalServerError, "Failed to generate compensation report")
		return
	}

	// Set appropriate headers for download
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"compensation_report_%s_%s.%s\"",
		reportType, time.Now().Format("20060102"), getFileExtension(contentType)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// CalculateMonthlyPayrollHandler calculates monthly payroll for a company
func (h *CompensationHandler) CalculateMonthlyPayrollHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	monthYearStr := r.URL.Query().Get("month_year")
	var monthYear time.Time
	if monthYearStr == "" {
		monthYear = time.Now().UTC()
	} else {
		monthYear, err = time.Parse("2006-01", monthYearStr)
		if err != nil {
			util.RespondWithError(w, http.StatusBadRequest, "Invalid month_year format. Use YYYY-MM")
			return
		}
	}

	payroll, err := h.compService.CalculateMonthlyPayroll(ctx, companyID, monthYear)
	if err != nil {
		h.logger.Error("Failed to calculate monthly payroll",
			util.String("company_id", companyID.String()),
			util.String("month_year", monthYear.Format("2006-01")),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusInternalServerError, "Failed to calculate monthly payroll")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"payroll":  payroll,
		"month":    monthYear.Format("2006-01"),
		"currency": "INR", // Default, should come from company settings
	})
}

// CalculateUserMonthlySalaryHandler calculates monthly salary for a user
func (h *CompensationHandler) CalculateUserMonthlySalaryHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "userID")

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	monthYearStr := r.URL.Query().Get("month_year")
	var monthYear time.Time
	if monthYearStr == "" {
		monthYear = time.Now().UTC()
	} else {
		monthYear, err = time.Parse("2006-01", monthYearStr)
		if err != nil {
			util.RespondWithError(w, http.StatusBadRequest, "Invalid month_year format. Use YYYY-MM")
			return
		}
	}

	salary, details, err := h.compService.CalculateUserMonthlySalary(ctx, userID, monthYear)
	if err != nil {
		h.logger.Error("Failed to calculate user monthly salary",
			util.String("user_id", userID.String()),
			util.String("month_year", monthYear.Format("2006-01")),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusInternalServerError, "Failed to calculate monthly salary")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"salary": map[string]interface{}{
			"amount":   salary,
			"currency": "INR",
		},
		"details": details,
		"month":   monthYear.Format("2006-01"),
	})
}

// ============================================================================
// SEARCH AND FILTER HANDLERS
// ============================================================================

// SearchCompensationStructuresHandler searches compensation structures
func (h *CompensationHandler) SearchCompensationStructuresHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Parse query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	} else if pageSize > 100 {
		pageSize = 100
	}

	// Build filters from query parameters
	filters := make(map[string]interface{})
	if structureCode := r.URL.Query().Get("structure_code"); structureCode != "" {
		filters["structure_code"] = structureCode
	}
	if name := r.URL.Query().Get("name"); name != "" {
		filters["name"] = name
	}
	if active := r.URL.Query().Get("active"); active != "" {
		filters["is_active"] = active == "true"
	}
	if currency := r.URL.Query().Get("currency"); currency != "" {
		filters["currency"] = currency
	}

	structures, totalCount, err := h.compQueryService.SearchCompensationStructures(ctx, companyID, filters, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to search compensation structures",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusInternalServerError, "Failed to search compensation structures")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":                 true,
		"compensation_structures": structures,
		"pagination": map[string]interface{}{
			"page":        page,
			"page_size":   pageSize,
			"total":       totalCount,
			"total_pages": (totalCount + pageSize - 1) / pageSize,
		},
		"filters": filters,
	})
}

// SearchUserCompensationsHandler searches user compensations
func (h *CompensationHandler) SearchUserCompensationsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Parse query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	} else if pageSize > 100 {
		pageSize = 100
	}

	// Build filters from query parameters
	filters := make(map[string]interface{})
	if userIDStr := r.URL.Query().Get("user_id"); userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err == nil {
			filters["user_id"] = userID
		}
	}
	if structureIDStr := r.URL.Query().Get("structure_id"); structureIDStr != "" {
		structureID, err := uuid.Parse(structureIDStr)
		if err == nil {
			filters["structure_id"] = structureID
		}
	}
	if effectiveFromStr := r.URL.Query().Get("effective_from"); effectiveFromStr != "" {
		effectiveFrom, err := time.Parse("2006-01-02", effectiveFromStr)
		if err == nil {
			filters["effective_from"] = effectiveFrom
		}
	}

	comps, totalCount, err := h.compQueryService.SearchUserCompensations(ctx, companyID, filters, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to search user compensations",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		util.RespondWithError(w, http.StatusInternalServerError, "Failed to search user compensations")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":            true,
		"user_compensations": comps,
		"pagination": map[string]interface{}{
			"page":        page,
			"page_size":   pageSize,
			"total":       totalCount,
			"total_pages": (totalCount + pageSize - 1) / pageSize,
		},
		"filters": filters,
	})
}

// ============================================================================
// BULK OPERATIONS HANDLERS
// ============================================================================

// AssignCompensationStructureToUsersHandler assigns compensation structure to multiple users
func (h *CompensationHandler) AssignCompensationStructureToUsersHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	structureIDStr := chi.URLParam(r, "structureID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	structureID, err := uuid.Parse(structureIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid structure ID")
		return
	}

	// Get actor info from context
	actorIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		util.RespondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	actorID, err := uuid.Parse(actorIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	actorType, _ := ctx.Value("session_type").(string)
	if actorType == "" {
		actorType = "admin"
	}

	var req struct {
		UserIDs       []uuid.UUID `json:"user_ids" validate:"required,min=1"`
		EffectiveFrom string      `json:"effective_from"`
		EffectiveTo   *string     `json:"effective_to,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.UserIDs) == 0 {
		util.RespondWithError(w, http.StatusBadRequest, "At least one user ID is required")
		return
	}

	// Parse effective from date
	var effectiveFrom time.Time
	if req.EffectiveFrom != "" {
		effectiveFrom, err = time.Parse(time.RFC3339, req.EffectiveFrom)
		if err != nil {
			effectiveFrom, err = time.Parse("2006-01-02", req.EffectiveFrom)
			if err != nil {
				util.RespondWithError(w, http.StatusBadRequest, "Invalid effective_from date format. Use RFC3339 or YYYY-MM-DD")
				return
			}
		}
	} else {
		effectiveFrom = time.Now().UTC()
	}

	// Parse effective to date if provided
	var effectiveToPtr *time.Time
	if req.EffectiveTo != nil {
		effectiveTo, err := time.Parse(time.RFC3339, *req.EffectiveTo)
		if err != nil {
			effectiveTo, err = time.Parse("2006-01-02", *req.EffectiveTo)
			if err != nil {
				util.RespondWithError(w, http.StatusBadRequest, "Invalid effective_to date format. Use RFC3339 or YYYY-MM-DD")
				return
			}
		}
		effectiveToPtr = &effectiveTo
	}

	userComps, err := h.compService.AssignCompensationStructureToUsers(
		ctx, companyID, structureID, req.UserIDs, effectiveFrom, effectiveToPtr, actorID, nil)
	if err != nil {
		h.logger.Error("Failed to assign compensation structure to users",
			util.String("company_id", companyID.String()),
			util.String("structure_id", structureID.String()),
			util.Int("user_count", len(req.UserIDs)),
			util.ErrorField(err))

		if err.Error() == "compensation structure not found" {
			util.RespondWithError(w, http.StatusNotFound, err.Error())
		} else if err.Error() == "compensation structure does not belong to company" {
			util.RespondWithError(w, http.StatusBadRequest, err.Error())
		} else if err.Error() == "cannot assign inactive compensation structure" {
			util.RespondWithError(w, http.StatusBadRequest, err.Error())
		} else {
			util.RespondWithError(w, http.StatusInternalServerError, "Failed to assign compensation structure to users")
		}
		return
	}

	util.RespondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success":            true,
		"user_compensations": userComps,
		"message":            fmt.Sprintf("Compensation structure assigned to %d users successfully", len(userComps)),
	})
}

// BulkAssignCompensationStructureHandler bulk assigns compensation structure
func (h *CompensationHandler) BulkAssignCompensationStructureHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	structureIDStr := chi.URLParam(r, "structureID")

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	structureID, err := uuid.Parse(structureIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid structure ID")
		return
	}

	// Get actor info from context
	actorIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		util.RespondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	actorID, err := uuid.Parse(actorIDStr)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	actorType, _ := ctx.Value("session_type").(string)
	if actorType == "" {
		actorType = "admin"
	}

	var req struct {
		UserCompensations []struct {
			UserID        uuid.UUID  `json:"user_id"`
			PayUnitID     *uuid.UUID `json:"pay_unit_id,omitempty"`
			CTCAmount     string     `json:"ctc_amount"`
			EffectiveFrom string     `json:"effective_from"`
			EffectiveTo   *string    `json:"effective_to,omitempty"`
		} `json:"user_compensations" validate:"required,min=1"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.UserCompensations) == 0 {
		util.RespondWithError(w, http.StatusBadRequest, "At least one user compensation is required")
		return
	}

	// Convert to service model
	var userComps []*compensation.UserCompensation
	for _, uc := range req.UserCompensations {
		ctcAmount, err := decimal.NewFromString(uc.CTCAmount)
		if err != nil {
			ctcAmount = decimal.Zero // Will be calculated from structure
		}

		effectiveFrom, err := time.Parse(time.RFC3339, uc.EffectiveFrom)
		if err != nil {
			effectiveFrom, err = time.Parse("2006-01-02", uc.EffectiveFrom)
			if err != nil {
				effectiveFrom = time.Now().UTC()
			}
		}

		var effectiveToPtr *time.Time
		if uc.EffectiveTo != nil {
			effectiveTo, err := time.Parse(time.RFC3339, *uc.EffectiveTo)
			if err != nil {
				effectiveTo, err = time.Parse("2006-01-02", *uc.EffectiveTo)
				if err == nil {
					effectiveToPtr = &effectiveTo
				}
			} else {
				effectiveToPtr = &effectiveTo
			}
		}

		userComp := &compensation.UserCompensation{
			UserID:        uc.UserID,
			StructureID:   structureID,
			PayUnitID:     uc.PayUnitID,
			CTCAmount:     ctcAmount,
			EffectiveFrom: effectiveFrom,
			EffectiveTo:   effectiveToPtr,
			AssignedBy:    &actorID,
			CreatedAt:     time.Now().UTC(),
		}

		userComps = append(userComps, userComp)
	}

	err = h.compService.BulkAssignCompensationStructure(ctx, companyID, structureID, userComps, actorType, actorID, nil)
	if err != nil {
		h.logger.Error("Failed to bulk assign compensation structure",
			util.String("company_id", companyID.String()),
			util.String("structure_id", structureID.String()),
			util.Int("compensation_count", len(userComps)),
			util.ErrorField(err))

		if err.Error() == "compensation structure not found" {
			util.RespondWithError(w, http.StatusNotFound, err.Error())
		} else if err.Error() == "compensation structure does not belong to company" {
			util.RespondWithError(w, http.StatusBadRequest, err.Error())
		} else if err.Error() == "cannot assign inactive compensation structure" {
			util.RespondWithError(w, http.StatusBadRequest, err.Error())
		} else {
			util.RespondWithError(w, http.StatusInternalServerError, "Failed to bulk assign compensation structure")
		}
		return
	}

	util.RespondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Compensation structure bulk assigned to %d users successfully", len(userComps)),
	})
}

// ============================================================================
// HEALTH CHECK HANDLER
// ============================================================================

// HealthCheckHandler performs a health check for compensation services
func (h *CompensationHandler) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check compensation service health
	if err := h.compService.HealthCheck(ctx); err != nil {
		h.logger.Error("Compensation service health check failed", util.ErrorField(err))
		util.RespondWithError(w, http.StatusServiceUnavailable, "Compensation service is unhealthy")
		return
	}

	// Check compensation query service health
	if err := h.compQueryService.HealthCheck(ctx); err != nil {
		h.logger.Error("Compensation query service health check failed", util.ErrorField(err))
		util.RespondWithError(w, http.StatusServiceUnavailable, "Compensation query service is unhealthy")
		return
	}

	util.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"status":  "healthy",
		"service": "compensation",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func getFileExtension(contentType string) string {
	switch contentType {
	case "text/csv":
		return "csv"
	case "application/json":
		return "json"
	case "application/vnd.ms-excel":
		return "xls"
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return "xlsx"
	default:
		return "txt"
	}
}

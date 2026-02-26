package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SalaryStructureHandler handles HTTP requests for salary structure management.
type SalaryStructureHandler struct {
	structService service.SalaryStructureService
	logger        *zap.Logger
}

// NewSalaryStructureHandler creates a new SalaryStructureHandler.
func NewSalaryStructureHandler(
	structService service.SalaryStructureService,
	logger *zap.Logger,
) *SalaryStructureHandler {
	return &SalaryStructureHandler{
		structService: structService,
		logger:        logger,
	}
}

// ---------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------

type createStructureRequest struct {
	StructureName string `json:"structure_name"`
	CurrencyCode  string `json:"currency_code"`
}

type updateStructureRequest struct {
	StructureName string `json:"structure_name"`
	CurrencyCode  string `json:"currency_code"`
}

type cloneStructureRequest struct {
	EffectiveFrom time.Time `json:"effective_from"`
}

type addComponentRequest struct {
	ComponentCode    string  `json:"component_code"`
	CalculationType  string  `json:"calculation_type"`
	Value            float64 `json:"value"`
	BasedOnComponent *string `json:"based_on_component,omitempty"`
	SequenceOrder    int     `json:"sequence_order"`
}

type updateComponentRequest struct {
	Value         float64 `json:"value"`
	SequenceOrder int     `json:"sequence_order"`
}

type reorderComponentsRequest struct {
	ComponentCodes []string `json:"component_codes"`
}

type assignStructureRequest struct {
	UserID        uuid.UUID `json:"user_id"`
	StructureID   uuid.UUID `json:"structure_id"`
	MonthlyCTC    float64   `json:"monthly_ctc"`
	PayType       string    `json:"pay_type"`
	EffectiveFrom time.Time `json:"effective_from"`
}

type bulkAssignStructureRequest struct {
	UserIDs       []uuid.UUID `json:"user_ids"`
	StructureID   uuid.UUID   `json:"structure_id"`
	MonthlyCTC    float64     `json:"monthly_ctc"`
	PayType       string      `json:"pay_type"`
	EffectiveFrom time.Time   `json:"effective_from"`
}

// ---------------------------------------------------------------------
// Structure CRUD
// ---------------------------------------------------------------------

// CreateStructure handles POST /companies/{companyID}/payroll/structures
func (h *SalaryStructureHandler) CreateStructure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req createStructureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.StructureName = strings.TrimSpace(req.StructureName)
	req.CurrencyCode = strings.TrimSpace(req.CurrencyCode)
	if req.StructureName == "" || req.CurrencyCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "structure_name and currency_code are required")
		return
	}

	input := &models.CreateSalaryStructureInput{
		CompanyID:     companyID,
		StructureName: req.StructureName,
		CurrencyCode:  req.CurrencyCode,
		CreatedBy:     actorID,
	}

	structure, err := h.structService.CreateStructure(ctx, input)
	if err != nil {
		h.logger.Error("failed to create salary structure", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    structure,
	})
}

// UpdateStructure handles PUT /companies/{companyID}/payroll/structures/{structureID}
func (h *SalaryStructureHandler) UpdateStructure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	structureID, err := uuid.Parse(chi.URLParam(r, "structureID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid structure id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req updateStructureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.StructureName = strings.TrimSpace(req.StructureName)
	req.CurrencyCode = strings.TrimSpace(req.CurrencyCode)
	if req.StructureName == "" || req.CurrencyCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "structure_name and currency_code are required")
		return
	}

	input := &models.UpdateSalaryStructureInput{
		StructureID:   structureID,
		CompanyID:     companyID,
		StructureName: req.StructureName,
		CurrencyCode:  req.CurrencyCode,
		UpdatedBy:     actorID,
	}

	structure, err := h.structService.UpdateStructure(ctx, input)
	if err != nil {
		h.logger.Error("failed to update salary structure", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    structure,
	})
}

// CloneStructure handles POST /companies/{companyID}/payroll/structures/{structureID}/clone
func (h *SalaryStructureHandler) CloneStructure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	structureID, err := uuid.Parse(chi.URLParam(r, "structureID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid structure id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req cloneStructureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.EffectiveFrom.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "effective_from is required")
		return
	}

	newStructure, err := h.structService.CloneStructure(ctx, companyID, structureID, req.EffectiveFrom, actorID)
	if err != nil {
		h.logger.Error("failed to clone salary structure", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    newStructure,
	})
}

// PublishStructure handles POST /companies/{companyID}/payroll/structures/{structureID}/publish
func (h *SalaryStructureHandler) PublishStructure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	structureID, err := uuid.Parse(chi.URLParam(r, "structureID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid structure id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if err := h.structService.PublishStructure(ctx, companyID, structureID, actorID); err != nil {
		h.logger.Error("failed to publish salary structure", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "salary structure published",
	})
}

// DeactivateStructure handles POST /companies/{companyID}/payroll/structures/{structureID}/deactivate
func (h *SalaryStructureHandler) DeactivateStructure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	structureID, err := uuid.Parse(chi.URLParam(r, "structureID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid structure id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if err := h.structService.DeactivateStructure(ctx, companyID, structureID, actorID); err != nil {
		h.logger.Error("failed to deactivate salary structure", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "salary structure deactivated",
	})
}

// ListStructures handles GET /companies/{companyID}/payroll/structures
func (h *SalaryStructureHandler) ListStructures(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	includeInactive := r.URL.Query().Get("include_inactive") == "true"

	filter := models.SalaryStructureFilter{
		CompanyID:       companyID,
		IncludeInactive: includeInactive,
	}

	structures, total, err := h.structService.ListStructures(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list salary structures", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"structures": structures,
			"total":      total,
		},
	})
}

// GetStructure handles GET /companies/{companyID}/payroll/structures/{structureID}
func (h *SalaryStructureHandler) GetStructure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	structureID, err := uuid.Parse(chi.URLParam(r, "structureID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid structure id")
		return
	}

	detail, err := h.structService.GetStructure(ctx, companyID, structureID)
	if err != nil {
		h.logger.Error("failed to get salary structure", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    detail,
	})
}

// ---------------------------------------------------------------------
// Component management
// ---------------------------------------------------------------------

// AddComponent handles POST /companies/{companyID}/payroll/structures/{structureID}/components
func (h *SalaryStructureHandler) AddComponent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	structureID, err := uuid.Parse(chi.URLParam(r, "structureID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid structure id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req addComponentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.ComponentCode = strings.TrimSpace(req.ComponentCode)
	req.CalculationType = strings.TrimSpace(req.CalculationType)
	if req.ComponentCode == "" || req.CalculationType == "" {
		h.respondWithError(w, http.StatusBadRequest, "component_code and calculation_type are required")
		return
	}

	input := &models.AddSalaryStructureComponentInput{
		StructureID:      structureID,
		CompanyID:        companyID,
		ComponentCode:    req.ComponentCode,
		CalculationType:  req.CalculationType,
		Value:            req.Value,
		BasedOnComponent: req.BasedOnComponent,
		SequenceOrder:    req.SequenceOrder,
	}

	if err := h.structService.AddComponent(ctx, input, actorID); err != nil {
		h.logger.Error("failed to add component to salary structure", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "component added",
	})
}

// UpdateComponent handles PUT /companies/{companyID}/payroll/structures/{structureID}/components/{componentCode}
func (h *SalaryStructureHandler) UpdateComponent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	structureID, err := uuid.Parse(chi.URLParam(r, "structureID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid structure id")
		return
	}
	componentCode := chi.URLParam(r, "componentCode")
	if componentCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "component code required")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req updateComponentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Fetch components with company validation to get the mapping ID
	components, err := h.structService.GetStructureComponents(ctx, companyID, structureID)
	if err != nil {
		h.logger.Error("failed to get structure components", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var mappingID uuid.UUID
	for _, comp := range components {
		if comp.ComponentCode == componentCode {
			mappingID = comp.MappingID
			break
		}
	}
	if mappingID == uuid.Nil {
		h.respondWithError(w, http.StatusNotFound, "component not found in this structure")
		return
	}

	input := &models.UpdateSalaryStructureComponentInput{
		MappingID:     mappingID,
		Value:         req.Value,
		SequenceOrder: req.SequenceOrder,
	}

	if err := h.structService.UpdateComponent(ctx, input, actorID); err != nil {
		h.logger.Error("failed to update component", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "component updated",
	})
}

// RemoveComponent handles DELETE /companies/{companyID}/payroll/structures/{structureID}/components/{componentCode}
func (h *SalaryStructureHandler) RemoveComponent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	structureID, err := uuid.Parse(chi.URLParam(r, "structureID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid structure id")
		return
	}
	componentCode := chi.URLParam(r, "componentCode")
	if componentCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "component code required")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if err := h.structService.RemoveComponent(ctx, companyID, structureID, componentCode, actorID); err != nil {
		h.logger.Error("failed to remove component", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "component removed",
	})
}

// ReorderComponents handles POST /companies/{companyID}/payroll/structures/{structureID}/reorder
func (h *SalaryStructureHandler) ReorderComponents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	structureID, err := uuid.Parse(chi.URLParam(r, "structureID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid structure id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req reorderComponentsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.ComponentCodes) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "component_codes cannot be empty")
		return
	}

	if err := h.structService.ReorderComponents(ctx, companyID, structureID, req.ComponentCodes, actorID); err != nil {
		h.logger.Error("failed to reorder components", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "components reordered",
	})
}

// ---------------------------------------------------------------------
// Assignment endpoints
// ---------------------------------------------------------------------

// AssignToEmployee handles POST /companies/{companyID}/payroll/structures/assign
func (h *SalaryStructureHandler) AssignToEmployee(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req assignStructureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Basic validation
	if req.UserID == uuid.Nil || req.StructureID == uuid.Nil || req.MonthlyCTC <= 0 || req.EffectiveFrom.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "user_id, structure_id, monthly_ctc, and effective_from are required")
		return
	}

	// Validate and default pay_type
	if req.PayType == "" {
		req.PayType = models.PayTypeMonthly
	}
	switch req.PayType {
	case models.PayTypeMonthly, models.PayTypeDailyWage, models.PayTypeHourly:
		// valid
	default:
		h.respondWithError(w, http.StatusBadRequest, "invalid pay_type, must be monthly, daily_wage, or hourly")
		return
	}

	input := &models.AssignSalaryStructureInput{
		CompanyID:     companyID,
		UserID:        req.UserID,
		StructureID:   req.StructureID,
		MonthlyCTC:    req.MonthlyCTC,
		PayType:       req.PayType,
		EffectiveFrom: req.EffectiveFrom,
		ActorID:       actorID,
	}

	if err := h.structService.AssignToEmployee(ctx, input); err != nil {
		h.logger.Error("failed to assign salary structure", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "salary structure assigned",
	})
}

// BulkAssignToEmployees handles POST /companies/{companyID}/payroll/structures/bulk-assign
func (h *SalaryStructureHandler) BulkAssignToEmployees(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req bulkAssignStructureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.UserIDs) == 0 || req.StructureID == uuid.Nil || req.MonthlyCTC <= 0 || req.EffectiveFrom.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "user_ids, structure_id, monthly_ctc, and effective_from are required")
		return
	}

	// Validate and default pay_type
	if req.PayType == "" {
		req.PayType = models.PayTypeMonthly
	}
	switch req.PayType {
	case models.PayTypeMonthly, models.PayTypeDailyWage, models.PayTypeHourly:
		// valid
	default:
		h.respondWithError(w, http.StatusBadRequest, "invalid pay_type, must be monthly, daily_wage, or hourly")
		return
	}

	input := &models.BulkAssignSalaryStructureInput{
		CompanyID:     companyID,
		UserIDs:       req.UserIDs,
		StructureID:   req.StructureID,
		MonthlyCTC:    req.MonthlyCTC,
		PayType:       req.PayType,
		EffectiveFrom: req.EffectiveFrom,
		ActorID:       actorID,
	}

	if err := h.structService.BulkAssignToEmployees(ctx, input); err != nil {
		h.logger.Error("failed to bulk assign salary structures", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "salary structures assigned",
	})
}

// ---------------------------------------------------------------------
// Helper methods
// ---------------------------------------------------------------------

// getAdminActor extracts the admin user ID from the context.
// Assumes that authentication middleware has set "session_type" and "user_id".
func (h *SalaryStructureHandler) getAdminActor(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("unauthenticated user")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, errors.New("invalid user_id in context")
	}

	return userID, nil
}

// respondWithJSON writes a JSON response.
func (h *SalaryStructureHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// respondWithError writes a JSON error response.
func (h *SalaryStructureHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}

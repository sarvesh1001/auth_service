package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"chatbot-service/internal/models"
)

type PayrollTool struct {
	hrClient *HRClient
}

func NewPayrollTool(hrClient *HRClient) *PayrollTool {
	return &PayrollTool{
		hrClient: hrClient,
	}
}

func (p *PayrollTool) Name() string {
	return "payroll"
}

func (p *PayrollTool) Execute(ctx context.Context, input models.ToolCallInput) (*models.ToolResult, error) {
	companyID, ok := input.CompanyID.(string)
	if !ok || companyID == "" {
		return nil, fmt.Errorf("company_id missing in context")
	}

	action, ok := input.Arguments["action"].(string)
	if !ok || action == "" {
		return nil, fmt.Errorf("action is required")
	}

	handler, exists := actionHandlers[action]
	if !exists {
		return nil, fmt.Errorf("unknown action: %s", action)
	}

	// Validate required body fields
	for _, field := range handler.requiredBody {
		val, ok := input.Arguments[field]
		if !ok || val == "" {
			return &models.ToolResult{
				ToolName:   p.Name(),
				Success:    false,
				HTTPStatus: 400,
				Error:      fmt.Sprintf("%s is required", field),
				Data:       nil,
			}, nil
		}
	}

	// Build path with parameters
	path, err := buildPath(handler.pathTemplate, input.Arguments)
	if err != nil {
		return &models.ToolResult{
			ToolName:   p.Name(),
			Success:    false,
			HTTPStatus: 400,
			Error:      err.Error(),
			Data:       nil,
		}, nil
	}

	// Add query parameters
	if len(handler.queryParams) > 0 {
		q := url.Values{}
		for _, param := range handler.queryParams {
			if val, ok := input.Arguments[param]; ok {
				if strVal, ok := val.(string); ok && strVal != "" {
					q.Set(param, strVal)
				}
			}
		}
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
	}

	// Build request body for POST/PUT
	var body []byte
	if handler.method == "POST" || handler.method == "PUT" {
		bodyMap := make(map[string]interface{})
		for k, v := range input.Arguments {
			// Skip action, path parameters, and query parameters
			if k == "action" || contains(handler.pathParams, k) || contains(handler.queryParams, k) {
				continue
			}
			bodyMap[k] = v
		}

		if len(bodyMap) > 0 {
			body, err = json.Marshal(bodyMap)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal request body: %w", err)
			}
		}
	}

	fullPath := fmt.Sprintf("/api/v1/companies/%s/payroll%s", companyID, path)

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	data, status, err := p.hrClient.Do(
		ctx,
		handler.method,
		fullPath,
		input.AuthHeader,
		input.DeviceID,
		companyID,
		bodyReader,
	)
	if err != nil {
		return nil, err
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}

	// Determine success based on status and optional "success" field
	if status >= 200 && status < 300 {
		if successVal, ok := parsed["success"]; ok {
			if b, ok := successVal.(bool); ok && !b {
				errMsg := extractErrorMessage(parsed)
				return &models.ToolResult{
					ToolName:   p.Name(),
					Success:    false,
					HTTPStatus: status,
					Error:      errMsg,
					Data:       nil,
				}, nil
			}
		}
		return &models.ToolResult{
			ToolName:   p.Name(),
			Success:    true,
			HTTPStatus: status,
			Data:       parsed,
		}, nil
	}

	// Non-2xx status
	errMsg := extractErrorMessage(parsed)
	return &models.ToolResult{
		ToolName:   p.Name(),
		Success:    false,
		HTTPStatus: status,
		Error:      errMsg,
		Data:       nil,
	}, nil
}

type actionHandler struct {
	method       string
	pathTemplate string
	pathParams   []string
	queryParams  []string
	requiredBody []string
}

var actionHandlers = map[string]actionHandler{
	// ----- Runs (existing) -----
	"list_runs": {
		method:       "GET",
		pathTemplate: "/runs",
		queryParams:  []string{"status", "period_start", "period_end", "page", "page_size"},
	},
	"get_run": {
		method:       "GET",
		pathTemplate: "/runs/{runID}",
		pathParams:   []string{"runID"},
	},
	"get_run_ledger": {
		method:       "GET",
		pathTemplate: "/runs/{runID}/ledger-summary",
		pathParams:   []string{"runID"},
	},
	"get_run_execution_status": {
		method:       "GET",
		pathTemplate: "/runs/{runID}/execution-status",
		pathParams:   []string{"runID"},
	},
	"list_employees_in_run": {
		method:       "GET",
		pathTemplate: "/runs/{runID}/employees",
		pathParams:   []string{"runID"},
	},
	"get_run_statutory_summary": {
		method:       "GET",
		pathTemplate: "/runs/{runID}/statutory-summary",
		pathParams:   []string{"runID"},
	},
	"export_run": {
		method:       "GET",
		pathTemplate: "/runs/{runID}/export",
		pathParams:   []string{"runID"},
	},
	"create_run": {
		method:       "POST",
		pathTemplate: "/runs",
		requiredBody: []string{"period_start", "period_end"},
	},
	"initialize_run": {
		method:       "POST",
		pathTemplate: "/runs/{runID}/initialize",
		pathParams:   []string{"runID"},
	},
	"execute_run": {
		method:       "POST",
		pathTemplate: "/runs/{runID}/execute",
		pathParams:   []string{"runID"},
	},
	"approve_run": {
		method:       "POST",
		pathTemplate: "/runs/{runID}/approve",
		pathParams:   []string{"runID"},
	},
	"cancel_run": {
		method:       "POST",
		pathTemplate: "/runs/{runID}/cancel",
		pathParams:   []string{"runID"},
	},
	"mark_run_paid": {
		method:       "POST",
		pathTemplate: "/runs/{runID}/mark-paid",
		pathParams:   []string{"runID"},
		requiredBody: []string{"paid_at"},
	},
	"reprocess_employee": {
		method:       "POST",
		pathTemplate: "/runs/{runID}/employees/{userID}/reprocess",
		pathParams:   []string{"runID", "userID"},
	},

	// ----- Employee Payroll History / YTD (existing) -----
	"get_employee_history": {
		method:       "GET",
		pathTemplate: "/employee/{userID}/history",
		pathParams:   []string{"userID"},
		queryParams:  []string{"from", "to"},
	},
	"get_employee_ytd": {
		method:       "GET",
		pathTemplate: "/employee/{userID}/ytd",
		pathParams:   []string{"userID"},
		queryParams:  []string{"financial_year_start"},
	},
	"get_employee_statutory_summary": {
		method:       "GET",
		pathTemplate: "/employee/{userID}/statutory-summary",
		pathParams:   []string{"userID"},
		queryParams:  []string{"financial_year_start"},
	},
	"get_employee_payslip": {
		method:       "GET",
		pathTemplate: "/payslip/{payrollItemID}",
		pathParams:   []string{"payrollItemID"},
	},

	// ----- Trends (existing) -----
	"get_payroll_trend": {
		method:       "GET",
		pathTemplate: "/trend",
		queryParams:  []string{"from", "to"},
	},
	"get_component_trend": {
		method:       "GET",
		pathTemplate: "/components/{componentCode}/trend",
		pathParams:   []string{"componentCode"},
		queryParams:  []string{"from", "to"},
	},

	// ----- Fines (existing + new) -----
	"list_fines": {
		method:       "GET",
		pathTemplate: "/fines",
		queryParams:  []string{"user_id", "is_processed", "from_date", "to_date", "page", "page_size"},
	},
	"get_fine": {
		method:       "GET",
		pathTemplate: "/fines/{fineID}",
		pathParams:   []string{"fineID"},
	},
	"get_fine_summary": {
		method:       "GET",
		pathTemplate: "/fines/summary",
		queryParams:  []string{"from_date", "to_date"},
	},
	"create_fine": {
		method:       "POST",
		pathTemplate: "/fines",
		requiredBody: []string{"user_id", "fine_amount", "fine_date"},
	},
	"update_fine": {
		method:       "PUT",
		pathTemplate: "/fines/{fineID}",
		pathParams:   []string{"fineID"},
	},
	"delete_fine": {
		method:       "DELETE",
		pathTemplate: "/fines/{fineID}",
		pathParams:   []string{"fineID"},
	},
	"process_fine": {
		method:       "PUT",
		pathTemplate: "/fines/{fineID}/process",
		pathParams:   []string{"fineID"},
		requiredBody: []string{"payroll_run_id"},
	},
	"lock_fines": {
		method:       "POST",
		pathTemplate: "/fines/lock-for-payroll-run",
		requiredBody: []string{"period_start", "period_end", "payroll_run_id"},
	},
	"get_employee_unprocessed_fines": {
		method:       "GET",
		pathTemplate: "/fines/employee/{userID}/unprocessed",
		pathParams:   []string{"userID"},
		queryParams:  []string{"from_date", "to_date"},
	},
	"get_employee_fine_summary": {
		method:       "GET",
		pathTemplate: "/fines/employee/{userID}/summary",
		pathParams:   []string{"userID"},
		queryParams:  []string{"from_date", "to_date"},
	},
	"create_fines_bulk": {
		method:       "POST",
		pathTemplate: "/fines/bulk",
		requiredBody: []string{"user_ids", "fine_amount", "reason", "fine_date"},
	},
	"bulk_delete_unprocessed_fines": {
		method:       "DELETE",
		pathTemplate: "/fines/bulk/unprocessed",
		requiredBody: []string{"fine_ids"},
	},

	// ----- Adjustments (existing + new) -----
	"list_adjustments": {
		method:       "GET",
		pathTemplate: "/adjustments",
		queryParams:  []string{"user_id", "component_code", "adjustment_type", "from_month", "to_month"},
	},
	"get_adjustment": {
		method:       "GET",
		pathTemplate: "/adjustments/{adjustmentID}",
		pathParams:   []string{"adjustmentID"},
	},
	"create_adjustment": {
		method:       "POST",
		pathTemplate: "/adjustments",
		requiredBody: []string{"user_id", "component_code", "amount", "adjustment_type", "applicable_month"},
	},
	"update_adjustment": {
		method:       "PUT",
		pathTemplate: "/adjustments/{adjustmentID}",
		pathParams:   []string{"adjustmentID"},
	},
	"delete_adjustment": {
		method:       "DELETE",
		pathTemplate: "/adjustments/{adjustmentID}",
		pathParams:   []string{"adjustmentID"},
	},
	"get_employee_adjustments": {
		method:       "GET",
		pathTemplate: "/employee/{userID}/adjustments",
		pathParams:   []string{"userID"},
		queryParams:  []string{"from", "to"},
	},
	"bulk_create_adjustments": {
		method:       "POST",
		pathTemplate: "/adjustments/bulk",
		requiredBody: []string{"adjustments"}, // expects array in body
	},

	// ----- Salary Structures (existing + new) -----
	"list_structures": {
		method:       "GET",
		pathTemplate: "/structures",
		queryParams:  []string{"include_inactive"},
	},
	"get_structure": {
		method:       "GET",
		pathTemplate: "/structures/{structureID}",
		pathParams:   []string{"structureID"},
	},
	"create_structure": {
		method:       "POST",
		pathTemplate: "/structures",
		requiredBody: []string{"structure_name", "currency_code"},
	},
	"assign_structure": {
		method:       "POST",
		pathTemplate: "/structures/assign",
		requiredBody: []string{"user_id", "structure_id", "monthly_ctc", "effective_from"},
	},
	"bulk_assign_structures": {
		method:       "POST",
		pathTemplate: "/structures/assign/bulk",
		requiredBody: []string{"user_ids", "structure_id", "monthly_ctc", "effective_from"},
	},
	"add_structure_component": {
		method:       "POST",
		pathTemplate: "/structures/{structureID}/components",
		pathParams:   []string{"structureID"},
		requiredBody: []string{"component_code", "calculation_type", "value", "sequence_order"},
	},
	"publish_structure": {
		method:       "POST",
		pathTemplate: "/structures/{structureID}/publish",
		pathParams:   []string{"structureID"},
	},
	"update_structure": {
		method:       "PUT",
		pathTemplate: "/structures/{structureID}",
		pathParams:   []string{"structureID"},
	},
	"update_structure_component": {
		method:       "PUT",
		pathTemplate: "/structures/{structureID}/components/{componentCode}",
		pathParams:   []string{"structureID", "componentCode"},
	},
	"delete_structure_component": {
		method:       "DELETE",
		pathTemplate: "/structures/{structureID}/components/{componentCode}",
		pathParams:   []string{"structureID", "componentCode"},
	},
	"reorder_structure_components": {
		method:       "POST",
		pathTemplate: "/structures/{structureID}/components/reorder",
		pathParams:   []string{"structureID"},
		requiredBody: []string{"component_codes"},
	},
	"clone_structure": {
		method:       "POST",
		pathTemplate: "/structures/{structureID}/clone",
		pathParams:   []string{"structureID"},
		requiredBody: []string{"effective_from"},
	},
	"deactivate_structure": {
		method:       "DELETE",
		pathTemplate: "/structures/{structureID}",
		pathParams:   []string{"structureID"},
	},

	// ----- Statutory Profiles (existing + new) -----
	"list_statutory_profiles": {
		method:       "GET",
		pathTemplate: "/statutory-profiles",
		queryParams:  []string{"user_id", "statutory_code", "active_on", "page", "page_size"},
	},
	"get_employee_active_profiles": {
		method:       "GET",
		pathTemplate: "/employee/{userID}/statutory-profiles/active",
		pathParams:   []string{"userID"},
		queryParams:  []string{"asOf"},
	},
	"create_statutory_profile": {
		method:       "POST",
		pathTemplate: "/statutory-profiles",
		requiredBody: []string{"user_id", "statutory_code", "effective_from"},
	},
	"update_statutory_profile": {
		method:       "PUT",
		pathTemplate: "/statutory-profiles/{profileID}",
		pathParams:   []string{"profileID"},
	},
	"deactivate_statutory_profile": {
		method:       "DELETE",
		pathTemplate: "/statutory-profiles/{profileID}",
		pathParams:   []string{"profileID"},
	},
	"change_tax_regime": {
		method:       "POST",
		pathTemplate: "/employee/{userID}/tax-regime",
		pathParams:   []string{"userID"},
		requiredBody: []string{"tax_regime_code", "effective_from"},
	},
	"bulk_upsert_statutory_profiles": {
		method:       "POST",
		pathTemplate: "/statutory-profiles/bulk",
		requiredBody: []string{"profiles"},
	},
	"get_employee_active_profile_for_code": {
		method:       "GET",
		pathTemplate: "/employee/{userID}/statutory-profiles/{statutoryCode}/active",
		pathParams:   []string{"userID", "statutoryCode"},
		queryParams:  []string{"asOf"},
	},
	"get_employee_profile_history": {
		method:       "GET",
		pathTemplate: "/employee/{userID}/statutory-profiles/{statutoryCode}/history",
		pathParams:   []string{"userID", "statutoryCode"},
	},

	// ----- Attendance Rules (existing + new) -----
	"list_attendance_rules": {
		method:       "GET",
		pathTemplate: "/attendance-rules",
		queryParams:  []string{"rule_type", "is_active", "based_on", "min_threshold", "page", "page_size"},
	},
	"get_attendance_rule": {
		method:       "GET",
		pathTemplate: "/attendance-rules/{ruleID}",
		pathParams:   []string{"ruleID"},
	},
	"create_attendance_rule": {
		method:       "POST",
		pathTemplate: "/attendance-rules",
		requiredBody: []string{"rule_type", "calculation_type", "value", "based_on", "threshold_minutes"},
	},
	"update_attendance_rule_version": {
		method:       "POST",
		pathTemplate: "/attendance-rules/{ruleID}/versions",
		pathParams:   []string{"ruleID"},
		requiredBody: []string{"rule_type", "calculation_type", "value", "based_on", "threshold_minutes"},
	},
	"activate_attendance_rule": {
		method:       "PUT",
		pathTemplate: "/attendance-rules/{ruleID}/activate",
		pathParams:   []string{"ruleID"},
	},
	"deactivate_attendance_rule": {
		method:       "PUT",
		pathTemplate: "/attendance-rules/{ruleID}/deactivate",
		pathParams:   []string{"ruleID"},
	},
	"bulk_deactivate_attendance_rules_by_type": {
		method:       "POST",
		pathTemplate: "/attendance-rules/bulk-deactivate-by-type",
		requiredBody: []string{"rule_type"},
	},
	"check_active_rule_exists": {
		method:       "GET",
		pathTemplate: "/attendance-rules/exists-active",
		queryParams:  []string{"rule_type"},
	},
	"get_active_attendance_rules": {
		method:       "GET",
		pathTemplate: "/attendance-rules/active",
		queryParams:  []string{"as_of"},
	},

	// ----- Statutory Component Definitions (existing) -----
	"create_statutory_component": {
		method:       "POST",
		pathTemplate: "/statutory-profiles/components",
		requiredBody: []string{"statutory_code", "description", "country_code", "calculation_basis"},
	},
	"list_statutory_components": {
		method:       "GET",
		pathTemplate: "/statutory-profiles/components",
		queryParams:  []string{"country_code", "calculation_basis"},
	},
	"update_statutory_component": {
		method:       "PUT",
		pathTemplate: "/statutory-profiles/components/{statutoryCode}",
		pathParams:   []string{"statutoryCode"},
		requiredBody: []string{"description", "calculation_basis", "has_employee", "has_employer"},
	},
	"delete_statutory_component": {
		method:       "DELETE",
		pathTemplate: "/statutory-profiles/components/{statutoryCode}",
		pathParams:   []string{"statutoryCode"},
	},

	// ----- Rule Sets (existing) -----
	"create_rule_set": {
		method:       "POST",
		pathTemplate: "/statutory-profiles/rule-sets",
		requiredBody: []string{"country_code", "version_label", "effective_from"},
	},
	"list_rule_sets": {
		method:       "GET",
		pathTemplate: "/statutory-profiles/rule-sets",
		queryParams:  []string{"page", "page_size", "is_active", "effective_on"},
	},
	"get_rule_set": {
		method:       "GET",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}",
		pathParams:   []string{"ruleSetID"},
	},
	"update_rule_set": {
		method:       "PUT",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}",
		pathParams:   []string{"ruleSetID"},
	},
	"deactivate_rule_set": {
		method:       "DELETE",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}",
		pathParams:   []string{"ruleSetID"},
	},
	"activate_rule_set": {
		method:       "POST",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/activate",
		pathParams:   []string{"ruleSetID"},
	},

	// ----- Contribution Rules (existing) -----
	"create_contribution_rule": {
		method:       "POST",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/contributions",
		pathParams:   []string{"ruleSetID"},
		requiredBody: []string{"statutory_code", "contribution_side", "calculation_type", "rate_value", "effective_from"},
	},
	"list_contribution_rules": {
		method:       "GET",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/contributions",
		pathParams:   []string{"ruleSetID"},
		queryParams:  []string{"statutory_code"},
	},
	"update_contribution_rule": {
		method:       "PUT",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/contributions/{ruleID}",
		pathParams:   []string{"ruleSetID", "ruleID"},
		requiredBody: []string{"statutory_code", "contribution_side", "calculation_type", "rate_value", "effective_from"},
	},
	"delete_contribution_rule": {
		method:       "DELETE",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/contributions/{ruleID}",
		pathParams:   []string{"ruleSetID", "ruleID"},
	},

	// ----- Tax Slabs (existing) -----
	"create_tax_slab": {
		method:       "POST",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/slabs",
		pathParams:   []string{"ruleSetID"},
		requiredBody: []string{"statutory_code", "min_amount", "max_amount", "rate", "is_percentage", "slab_order", "effective_from"},
	},
	"list_tax_slabs": {
		method:       "GET",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/slabs",
		pathParams:   []string{"ruleSetID"},
		queryParams:  []string{"statutory_code"},
	},
	"update_tax_slab": {
		method:       "PUT",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/slabs/{slabID}",
		pathParams:   []string{"ruleSetID", "slabID"},
		requiredBody: []string{"min_amount", "max_amount", "rate", "is_percentage", "slab_order", "effective_from"},
	},
	"delete_tax_slab": {
		method:       "DELETE",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/slabs/{slabID}",
		pathParams:   []string{"ruleSetID", "slabID"},
	},

	// ----- Deduction Limits (existing) -----
	"create_deduction_limit": {
		method:       "POST",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/limits",
		pathParams:   []string{"ruleSetID"},
		requiredBody: []string{"limit_code", "limit_value"},
	},
	"list_deduction_limits": {
		method:       "GET",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/limits",
		pathParams:   []string{"ruleSetID"},
	},
	"update_deduction_limit": {
		method:       "PUT",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/limits/{limitID}",
		pathParams:   []string{"ruleSetID", "limitID"},
		requiredBody: []string{"limit_value"},
	},
	"delete_deduction_limit": {
		method:       "DELETE",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/limits/{limitID}",
		pathParams:   []string{"ruleSetID", "limitID"},
	},

	// ----- Component Mappings (existing + new) -----
	"create_component_mapping": {
		method:       "POST",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/mappings",
		pathParams:   []string{"ruleSetID"},
		requiredBody: []string{"statutory_code", "component_code", "effective_from"},
	},
	"bulk_create_component_mappings": {
		method:       "POST",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/mappings/bulk",
		pathParams:   []string{"ruleSetID"},
		requiredBody: []string{"statutory_code", "component_codes", "effective_from"},
	},
	"list_component_mappings": {
		method:       "GET",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/mappings",
		pathParams:   []string{"ruleSetID"},
		queryParams:  []string{"statutory_code"},
	},
	"update_component_mapping": {
		method:       "PUT",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/mappings/{mappingId}",
		pathParams:   []string{"ruleSetID", "mappingId"},
		requiredBody: []string{"component_code", "effective_from", "version"},
	},
	"delete_component_mapping": {
		method:       "DELETE",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/mappings/{mappingId}",
		pathParams:   []string{"ruleSetID", "mappingId"},
	},

	// ----- Payroll Locks (new) -----
	"list_locks": {
		method:       "GET",
		pathTemplate: "/locks",
	},
	"create_lock": {
		method:       "POST",
		pathTemplate: "/locks",
		requiredBody: []string{"period_start", "period_end", "reason"},
	},
	"delete_lock": {
		method:       "DELETE",
		pathTemplate: "/locks",
		queryParams:  []string{"start", "end"},
	},

	// ----- Payroll Components (new) -----
	"list_components": {
		method:       "GET",
		pathTemplate: "/components",
	},
	"get_component": {
		method:       "GET",
		pathTemplate: "/components/{componentCode}",
		pathParams:   []string{"componentCode"},
	},
	"create_component": {
		method:       "POST",
		pathTemplate: "/components",
		requiredBody: []string{"component_code", "component_type", "description", "is_taxable", "is_system", "is_active", "contribution_side"},
	},
	"update_component": {
		method:       "PUT",
		pathTemplate: "/components/{componentCode}",
		pathParams:   []string{"componentCode"},
	},
	"get_default_component": {
		method:       "GET",
		pathTemplate: "/components/default",
		queryParams:  []string{"purpose"},
	},
	"clear_component_cache": {
		method:       "POST",
		pathTemplate: "/components/clear-cache",
	},

	// ----- Company Payroll Settings (new) -----
	"get_company_settings": {
		method:       "GET",
		pathTemplate: "/settings",
	},
	"update_company_settings": {
		method:       "PUT",
		pathTemplate: "/settings",
		requiredBody: []string{"default_fine_component", "default_arrears_component", "default_loan_component", "default_basic_component"},
	},

	// ----- Loans (new) -----
	"list_loans": {
		method:       "GET",
		pathTemplate: "/loans",
		queryParams:  []string{"user_id", "include_closed"},
	},
	"list_active_loans": {
		method:       "GET",
		pathTemplate: "/loans/active",
		queryParams:  []string{"as_of"},
	},
	"get_loan_pending_emis": {
		method:       "GET",
		pathTemplate: "/loans/{loanId}/pending-emis",
		pathParams:   []string{"loanId"},
	},
	"close_loan": {
		method:       "POST",
		pathTemplate: "/loans/{loanId}/close",
		pathParams:   []string{"loanId"},
		requiredBody: []string{"closure_date"},
	},
	"preview_emi": {
		method:       "POST",
		pathTemplate: "/loans/preview-emi",
		requiredBody: []string{"user_id", "principal", "total_emis"},
	},
	"get_loans_for_user": {
		method:       "GET",
		pathTemplate: "/loans/user/{userId}",
		pathParams:   []string{"userId"},
		queryParams:  []string{"includeClosed"},
	},
	"record_manual_loan_payment": {
		method:       "POST",
		pathTemplate: "/loans/{loanId}/manual-payment",
		pathParams:   []string{"loanId"},
		requiredBody: []string{"amount", "paid_at"},
	},
	"list_loan_payments": {
		method:       "GET",
		pathTemplate: "/loans/{loanId}/payments",
		pathParams:   []string{"loanId"},
	},
	"get_pending_emis_for_run": {
		method:       "GET",
		pathTemplate: "/runs/{payrollRunId}/pending-emis",
		pathParams:   []string{"payrollRunId"},
	},
	"mark_emi_paid": {
		method:       "POST",
		pathTemplate: "/emis/{emiId}/paid",
		pathParams:   []string{"emiId"},
		requiredBody: []string{"paid_date"},
	},

	// ----- Arrears (new) -----
	"create_arrears": {
		method:       "POST",
		pathTemplate: "/arrears",
		requiredBody: []string{"user_id", "effective_from", "effective_to", "amount", "reason"},
	},
	"get_employee_unprocessed_arrears": {
		method:       "GET",
		pathTemplate: "/employee/{userId}/arrears/unprocessed",
		pathParams:   []string{"userId"},
	},
	"list_unprocessed_arrears": {
		method:       "GET",
		pathTemplate: "/arrears/unprocessed",
		queryParams:  []string{"period_start", "period_end"},
	},

	// ----- Employee Payroll Queries (new) -----
	"get_employee_salary": {
		method:       "GET",
		pathTemplate: "/employee/{userId}/salary",
		pathParams:   []string{"userId"},
		queryParams:  []string{"as_of"},
	},
	"get_employee_salary_snapshot": {
		method:       "GET",
		pathTemplate: "/employee/{userId}/salary/snapshot",
		pathParams:   []string{"userId"},
		queryParams:  []string{"as_of"},
	},
	"preview_earnings": {
		method:       "POST",
		pathTemplate: "/employee/{userId}/earnings/preview",
		pathParams:   []string{"userId"},
		requiredBody: []string{"period_start", "period_end"},
	},

	// ----- Payslips (new) -----
	"generate_payslips_for_run": {
		method:       "POST",
		pathTemplate: "/payslips/runs/{runId}/generate",
		pathParams:   []string{"runId"},
		requiredBody: []string{}, // empty body
	},
	"download_payslip": {
		method:       "GET",
		pathTemplate: "/payslips/runs/{runId}/users/{userId}/download",
		pathParams:   []string{"runId", "userId"},
	},
	"send_payslip_email": {
		method:       "POST",
		pathTemplate: "/payslips/runs/{runId}/users/{userId}/send-email",
		pathParams:   []string{"runId", "userId"},
		requiredBody: []string{},
	},
	"list_employee_payslips": {
		method:       "GET",
		pathTemplate: "/payslips/users/{userId}",
		pathParams:   []string{"userId"},
		queryParams:  []string{"from", "to"},
	},

	// ----- Reports (new) -----
	"generate_statutory_challan": {
		method:       "POST",
		pathTemplate: "/reports/statutory-challan",
		requiredBody: []string{"period_start", "period_end"},
	},
	"generate_payroll_register": {
		method:       "POST",
		pathTemplate: "/reports/payroll-register",
		requiredBody: []string{"period_start", "period_end"},
		queryParams:  []string{"group_by"},
	},

	// ----- Tax Declarations (new) -----
	"create_declaration_type": {
		method:       "POST",
		pathTemplate: "/tax-declarations/types",
		requiredBody: []string{"type_code", "description", "max_limit"},
	},
	"update_declaration_type": {
		method:       "PUT",
		pathTemplate: "/tax-declarations/types/{typeCode}",
		pathParams:   []string{"typeCode"},
	},
	"list_declaration_types": {
		method:       "GET",
		pathTemplate: "/tax-declarations/types",
	},
	"get_declaration_type": {
		method:       "GET",
		pathTemplate: "/tax-declarations/types/{typeCode}",
		pathParams:   []string{"typeCode"},
	},
	"create_declaration": {
		method:       "POST",
		pathTemplate: "/tax-declarations/declarations",
		requiredBody: []string{"user_id", "financial_year", "declaration_type", "amount"},
	},
	"update_declaration": {
		method:       "PUT",
		pathTemplate: "/tax-declarations/declarations/{declarationId}",
		pathParams:   []string{"declarationId"},
	},
	"verify_declaration": {
		method:       "POST",
		pathTemplate: "/tax-declarations/declarations/{declarationId}/verify",
		pathParams:   []string{"declarationId"},
		requiredBody: []string{"status"},
	},
	"list_user_declarations": {
		method:       "GET",
		pathTemplate: "/tax-declarations/declarations/user/{userId}",
		pathParams:   []string{"userId"},
		queryParams:  []string{"financial_year"},
	},
	"list_declarations": {
		method:       "GET",
		pathTemplate: "/tax-declarations/declarations",
		queryParams:  []string{"financial_year", "status"},
	},
	"get_declaration_total": {
		method:       "GET",
		pathTemplate: "/tax-declarations/declarations/total",
		queryParams:  []string{"user_id", "financial_year", "only_verified"},
	},

	// ----- Bank Export (new) -----
	"export_bank_file": {
		method:       "GET",
		pathTemplate: "/runs/{runId}/bank-export",
		pathParams:   []string{"runId"},
		queryParams:  []string{"format"},
	},

	// ----- Component Management (new) -----
	"list_component_management": {
		method:       "GET",
		pathTemplate: "/component-management",
	},
	"create_component_management": {
		method:       "POST",
		pathTemplate: "/component-management",
		requiredBody: []string{"component_code", "component_type", "description", "is_taxable", "is_system", "is_active", "contribution_side"},
	},
	"update_component_management": {
		method:       "PUT",
		pathTemplate: "/component-management/{componentCode}",
		pathParams:   []string{"componentCode"},
	},
	"delete_component_management": {
		method:       "DELETE",
		pathTemplate: "/component-management/{componentCode}",
		pathParams:   []string{"componentCode"},
	},
}

// buildPath replaces path parameters in the template with values from args.
func buildPath(template string, args map[string]interface{}) (string, error) {
	path := template
	for {
		start := strings.Index(path, "{")
		if start == -1 {
			break
		}
		end := strings.Index(path, "}")
		if end == -1 || end < start {
			return "", fmt.Errorf("malformed path template: %s", template)
		}
		param := path[start+1 : end]
		val, ok := args[param]
		if !ok {
			return "", fmt.Errorf("missing path parameter: %s", param)
		}
		strVal, ok := val.(string)
		if !ok || strVal == "" {
			return "", fmt.Errorf("path parameter %s must be a non‑empty string", param)
		}
		path = path[:start] + strVal + path[end+1:]
	}
	return path, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// extractErrorMessage tries to get an error message from various possible fields.
func extractErrorMessage(parsed map[string]interface{}) string {
	if err, ok := parsed["error"].(string); ok && err != "" {
		return err
	}
	if msg, ok := parsed["message"].(string); ok && msg != "" {
		return msg
	}
	return "HR service returned an error"
}

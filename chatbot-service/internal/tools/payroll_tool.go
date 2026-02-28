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
	// ----- Runs -----
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

	// ----- Employee Payroll History / YTD -----
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

	// ----- Trends -----
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

	// ----- Fines -----
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

	// ----- Adjustments -----
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

	// ----- Salary Structures -----
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

	// ----- Statutory Profiles -----
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

	// ----- Attendance Rules -----
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

	// ----- Statutory Component Definitions -----
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

	// ----- Rule Sets -----
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

	// ----- Contribution Rules -----
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

	// ----- Tax Slabs -----
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

	// ----- Deduction Limits -----
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

	// ----- Component Mappings -----
	"create_component_mapping": {
		method:       "POST",
		pathTemplate: "/statutory-profiles/rule-sets/{ruleSetID}/mappings",
		pathParams:   []string{"ruleSetID"},
		requiredBody: []string{"statutory_code", "component_code", "effective_from"},
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

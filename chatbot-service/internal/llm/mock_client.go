package llm

import (
	"context"
	"strings"
)

type MockClient struct{}

func NewMockClient() *MockClient {
	return &MockClient{}
}

// mergeArgs merges the original request arguments into the base map,
// preserving any user‑provided values. The "action" key from the user
// is ignored because the mock client already sets the intended action.
func mergeArgs(base map[string]interface{}, reqArgs map[string]interface{}) map[string]interface{} {
	for k, v := range reqArgs {
		if k == "action" {
			continue // preserve the action set by the mock client
		}
		base[k] = v
	}
	return base
}

func (m *MockClient) Process(ctx context.Context, req Request) (*Response, error) {
	lower := strings.ToLower(req.Message)

	// ----- Payroll Runs -----
	if strings.Contains(lower, "list runs") || strings.Contains(lower, "show runs") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "list_runs"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "get run") && (strings.Contains(lower, "details") || strings.Contains(lower, "single")) {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_run"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "run ledger") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_run_ledger"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "run execution status") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_run_execution_status"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "employees in run") || strings.Contains(lower, "run employees") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "list_employees_in_run"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "run statutory summary") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_run_statutory_summary"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "export run") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "export_run"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "create run") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "create_run"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "initialize run") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "initialize_run"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "execute run") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "execute_run"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "approve run") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "approve_run"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "cancel run") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "cancel_run"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "mark run paid") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "mark_run_paid"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "reprocess employee") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "reprocess_employee"}, req.Arguments),
			},
		}, nil
	}

	// ----- Employee Payroll History / YTD -----
	if strings.Contains(lower, "employee history") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_employee_history"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "ytd") || strings.Contains(lower, "year to date") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_employee_ytd"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "employee statutory summary") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_employee_statutory_summary"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "payslip") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_employee_payslip"}, req.Arguments),
			},
		}, nil
	}

	// ----- Trends -----
	if strings.Contains(lower, "payroll trend") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_payroll_trend"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "component trend") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_component_trend"}, req.Arguments),
			},
		}, nil
	}

	// ----- Fines -----
	if strings.Contains(lower, "list fines") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "list_fines"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "get fine") && strings.Contains(lower, "details") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_fine"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "fine summary") || strings.Contains(lower, "total fines") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_fine_summary"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "create fine") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "create_fine"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "update fine") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "update_fine"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "delete fine") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "delete_fine"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "process fine") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "process_fine"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "lock fines") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "lock_fines"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "employee unprocessed fines") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_employee_unprocessed_fines"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "employee fine summary") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_employee_fine_summary"}, req.Arguments),
			},
		}, nil
	}

	// ----- Adjustments -----
	if strings.Contains(lower, "list adjustments") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "list_adjustments"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "get adjustment") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_adjustment"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "create adjustment") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "create_adjustment"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "update adjustment") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "update_adjustment"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "delete adjustment") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "delete_adjustment"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "employee adjustments") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_employee_adjustments"}, req.Arguments),
			},
		}, nil
	}

	// ----- Salary Structures -----
	if strings.Contains(lower, "list structures") || strings.Contains(lower, "salary structures") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "list_structures"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "get structure") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_structure"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "create structure") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "create_structure"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "assign structure") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "assign_structure"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "bulk assign structures") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "bulk_assign_structures"}, req.Arguments),
			},
		}, nil
	}

	// ----- Statutory Profiles -----
	if strings.Contains(lower, "list statutory profiles") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "list_statutory_profiles"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "employee active profiles") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_employee_active_profiles"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "create statutory profile") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "create_statutory_profile"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "update statutory profile") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "update_statutory_profile"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "deactivate statutory profile") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "deactivate_statutory_profile"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "change tax regime") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "change_tax_regime"}, req.Arguments),
			},
		}, nil
	}

	// ----- Attendance Rules -----
	if strings.Contains(lower, "list attendance rules") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "list_attendance_rules"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "get attendance rule") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "get_attendance_rule"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "create attendance rule") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "create_attendance_rule"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "update attendance rule version") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "update_attendance_rule_version"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "activate attendance rule") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "activate_attendance_rule"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "deactivate attendance rule") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "deactivate_attendance_rule"}, req.Arguments),
			},
		}, nil
	}

	// --- Statutory Component Definitions ---
	if strings.Contains(lower, "create statutory component") || strings.Contains(lower, "add statutory component") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "create_statutory_component"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "list statutory components") || strings.Contains(lower, "show statutory components") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "list_statutory_components"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "update statutory component") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "update_statutory_component"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "delete statutory component") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "delete_statutory_component"}, req.Arguments),
			},
		}, nil
	}

	// --- Rule Sets ---
	if strings.Contains(lower, "create rule set") || strings.Contains(lower, "new rule set") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "create_rule_set"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "list rule sets") || strings.Contains(lower, "show rule sets") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "list_rule_sets"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "update rule set") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "update_rule_set"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "deactivate rule set") || strings.Contains(lower, "delete rule set") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "deactivate_rule_set"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "activate rule set") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "activate_rule_set"}, req.Arguments),
			},
		}, nil
	}

	// --- Contribution Rules ---
	if strings.Contains(lower, "add contribution rule") || strings.Contains(lower, "create contribution") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "create_contribution_rule"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "list contribution rules") || strings.Contains(lower, "show contribution rules") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "list_contribution_rules"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "update contribution rule") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "update_contribution_rule"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "delete contribution rule") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "delete_contribution_rule"}, req.Arguments),
			},
		}, nil
	}

	// --- Tax Slabs ---
	if strings.Contains(lower, "add tax slab") || strings.Contains(lower, "create income tax slab") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "create_tax_slab"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "list tax slabs") || strings.Contains(lower, "show tax slabs") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "list_tax_slabs"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "update tax slab") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "update_tax_slab"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "delete tax slab") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "delete_tax_slab"}, req.Arguments),
			},
		}, nil
	}

	// --- Deduction Limits ---
	if strings.Contains(lower, "add deduction limit") || strings.Contains(lower, "create limit 80c") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "create_deduction_limit"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "list deduction limits") || strings.Contains(lower, "show deduction limits") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "list_deduction_limits"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "update deduction limit") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "update_deduction_limit"}, req.Arguments),
			},
		}, nil
	}
	if strings.Contains(lower, "delete deduction limit") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "delete_deduction_limit"}, req.Arguments),
			},
		}, nil
	}

	// --- Component Mappings ---
	if strings.Contains(lower, "add component mapping") || strings.Contains(lower, "map component") {
		return &Response{
			ToolCall: &ToolCall{
				Name:      "payroll",
				Arguments: mergeArgs(map[string]interface{}{"action": "create_component_mapping"}, req.Arguments),
			},
		}, nil
	}

	// Default text response
	return &Response{
		Content: "I understand your request. How can I assist you further?",
	}, nil
}

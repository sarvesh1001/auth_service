package tools

import (
	"chatbot-service/internal/models"
	"context"
	"encoding/json"
	"fmt"
	"time"
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
	return "payroll_summary"
}

func (p *PayrollTool) Execute(
	ctx context.Context,
	input models.ToolCallInput,
) (*models.ToolResult, error) {

	// ----------------------------------------------------
	// Validate month
	// ----------------------------------------------------
	month, ok := input.Arguments["month"].(string)
	if !ok || month == "" {
		return nil, fmt.Errorf("month is required (format: YYYY-MM)")
	}

	// ----------------------------------------------------
	// Validate companyID
	// ----------------------------------------------------
	companyID, ok := input.CompanyID.(string)
	if !ok || companyID == "" {
		return nil, fmt.Errorf("company_id missing in context")
	}

	// ----------------------------------------------------
	// Convert month → from/to range
	// ----------------------------------------------------
	from := month + "-01"

	t, err := time.Parse("2006-01-02", from)
	if err != nil {
		return nil, fmt.Errorf("invalid month format, use YYYY-MM")
	}

	to := t.AddDate(0, 1, -1).Format("2006-01-02")

	// ----------------------------------------------------
	// Build HR route
	// ----------------------------------------------------
	path := fmt.Sprintf(
		"/api/v1/companies/%s/payroll/trend?from=%s&to=%s",
		companyID,
		from,
		to,
	)

	// ----------------------------------------------------
	// Call HR service
	// ----------------------------------------------------
	data, status, err := p.hrClient.Do(
		ctx,
		"GET",
		path,
		input.AuthHeader,
		input.DeviceID, // <-- ADDED: forward device_id
		companyID,      // <-- ADDED: forward company_id
		nil,
	)
	if err != nil {
		return nil, err
	}

	// ----------------------------------------------------
	// Parse HR response
	// HR format:
	// {
	//   "success": bool,
	//   "data": ...,
	//   "error": ...
	// }
	// ----------------------------------------------------
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}

	// ----------------------------------------------------
	// If HR rejected (permission/session/etc)
	// ----------------------------------------------------
	if status != 200 {
		return &models.ToolResult{
			ToolName: p.Name(),
			Success:  false,
			Data:     parsed,
		}, nil
	}

	// ----------------------------------------------------
	// Success
	// ----------------------------------------------------
	return &models.ToolResult{
		ToolName: p.Name(),
		Success:  true,
		Data:     parsed["data"],
	}, nil
}

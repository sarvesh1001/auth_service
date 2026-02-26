package llm

import (
	"context"
	"strings"
	"time"
)

type MockClient struct{}

func NewMockClient() *MockClient {
	return &MockClient{}
}

func (m *MockClient) Process(ctx context.Context, req Request) (*Response, error) {
	if strings.Contains(strings.ToLower(req.Message), "payroll") {
		return &Response{
			ToolCall: &ToolCall{
				Name: "payroll_summary",
				Arguments: map[string]interface{}{
					"month": time.Now().Format("2006-01"),
				},
			},
		}, nil
	}

	return &Response{
		Content: "I understand your request.",
	}, nil
}

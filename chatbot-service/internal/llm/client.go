package llm

import "context"

type Client interface {
	Process(ctx context.Context, req Request) (*Response, error)
}

type Request struct {
	UserID  string
	Message string
}

type Response struct {
	Content  string
	ToolCall *ToolCall
}

type ToolCall struct {
	Name      string
	Arguments map[string]interface{}
}

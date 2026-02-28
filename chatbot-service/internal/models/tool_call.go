package models

type ToolCall struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type ToolResult struct {
	ToolName   string      `json:"tool_name"`
	Success    bool        `json:"success"`
	HTTPStatus int         `json:"-"` // internal use only, not returned to client
	Data       interface{} `json:"data,omitempty"`
	Error      string      `json:"error,omitempty"`
}

type ToolCallInput struct {
	UserID         string
	CompanyID      interface{}
	SessionType    string
	PermissionMask interface{}
	AuthHeader     string
	DeviceID       string
	Arguments      map[string]interface{}
}

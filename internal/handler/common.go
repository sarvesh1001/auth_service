package handler

import "time"

// Response is a common response structure used across all handlers
type Response struct {
    Success   bool        `json:"success"`
    Data      interface{} `json:"data,omitempty"`
    Error     string      `json:"error,omitempty"`
    Message   string      `json:"message"`
    Meta      interface{} `json:"meta,omitempty"`
    Timestamp time.Time   `json:"timestamp"` // ✅ FIXED: Proper field name
}

// Meta represents pagination metadata
type Meta struct {
    PageToken string `json:"page_token,omitempty"`
    Total     int    `json:"total,omitempty"`
    PageSize  int    `json:"page_size,omitempty"`
}

// successResponse creates a successful response
func successResponse(data interface{}, message string) Response {
    return Response{
        Success:   true, // ✅ FIXED: Proper field assignment
        Data:      data,
        Message:   message,
        Timestamp: time.Now().UTC(),
    }
}

// errorResponse creates an error response
func errorResponse(err error, message string) Response {
    return Response{
        Success:   false, // ✅ FIXED: Proper field assignment
        Error:     err.Error(),
        Message:   message,
        Timestamp: time.Now().UTC(),
    }
}
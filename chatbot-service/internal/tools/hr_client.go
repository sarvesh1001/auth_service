package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type HRClient struct {
	BaseURL string
	Client  *http.Client
}

func NewHRClient(baseURL string) *HRClient {
	return &HRClient{
		BaseURL: baseURL,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// UPDATED: added deviceID and companyID parameters
func (c *HRClient) Do(
	ctx context.Context,
	method string,
	path string,
	authHeader string,
	deviceID string,
	companyID string,
	body interface{},
) ([]byte, int, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		method,
		fmt.Sprintf("%s%s", c.BaseURL, path),
		bodyReader,
	)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)
	// NEW: set required headers
	req.Header.Set("X-Device-ID", deviceID)
	req.Header.Set("X-Company-ID", companyID)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return data, resp.StatusCode, nil
}

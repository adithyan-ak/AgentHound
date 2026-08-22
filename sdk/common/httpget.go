package common

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/contact"
)

// NoRedirectClient returns the service-collector HTTP client: a fixed
// timeout and a CheckRedirect that stops at the first response (collectors
// probe a specific endpoint and must not be bounced to an arbitrary host
// by a 30x).
func NoRedirectClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: contact.GuardTransport(nil),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// GetJSON performs the GET-and-read dance shared by service collectors: build a
// GET request, set Accept: application/json, optionally attach a Bearer
// token, execute, and read at most limit bytes of the body. A Bearer
// header is attached only when bearer != "". A non-2xx status is returned
// as an error. The raw body is returned as []byte; callers unmarshal it
// themselves (response shapes differ per service).
func GetJSON(ctx context.Context, client *http.Client, url, bearer string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
}

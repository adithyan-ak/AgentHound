package a2a

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/common"
)

type RawCard struct {
	URL      string
	Body     []byte
	Parsed   map[string]any
	Version  string
	CardHash string
}

const (
	v10Path    = "/.well-known/agent-card.json"
	v030Path   = "/.well-known/agent.json"
	maxBodyLen = 5 * 1024 * 1024
)

func FetchAgentCard(ctx context.Context, targetURL string, authToken string, insecure bool) (*RawCard, error) {
	base := normalizeBaseURL(targetURL)

	transport := &http.Transport{}
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects (max 5)")
			}
			return nil
		},
	}

	card, err := fetchCard(ctx, client, base+v10Path, authToken)
	if err != nil {
		if fe, ok := err.(*FetchError); ok && fe.StatusCode == 404 {
			card, err = fetchCard(ctx, client, base+v030Path, authToken)
			if err != nil {
				return nil, fmt.Errorf("agent card not found at %s: %w", base, err)
			}
		} else {
			return nil, err
		}
	}

	card.URL = base
	return card, nil
}

type FetchError struct {
	StatusCode int
	URL        string
	Message    string
}

func (e *FetchError) Error() string {
	return fmt.Sprintf("fetch %s: %s (status %d)", e.URL, e.Message, e.StatusCode)
}

func fetchCard(ctx context.Context, client *http.Client, url string, authToken string) (*RawCard, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", url, err)
	}
	req.Header.Set("Accept", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &FetchError{
			StatusCode: resp.StatusCode,
			URL:        url,
			Message:    fmt.Sprintf("non-200 response: %s", resp.Status),
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyLen))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", url, err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("parse JSON from %s: %w", url, err)
	}

	version := DetectVersion(parsed)
	cardHash := common.HashSHA256(string(body))

	return &RawCard{
		Body:     body,
		Parsed:   parsed,
		Version:  version,
		CardHash: cardHash,
	}, nil
}

func normalizeBaseURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	rawURL = strings.TrimRight(rawURL, "/")
	rawURL = strings.TrimSuffix(rawURL, v10Path)
	rawURL = strings.TrimSuffix(rawURL, v030Path)
	return rawURL
}

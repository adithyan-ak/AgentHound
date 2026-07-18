package a2a

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/common"
)

type RawCard struct {
	Parsed              map[string]any
	Version             string
	CardHash            string
	JSONValidationError string
}

const (
	v10Path    = common.A2AWellKnownCardPath
	v030Path   = common.A2AWellKnownLegacyPath
	maxBodyLen = 5 * 1024 * 1024
)

func FetchAgentCard(ctx context.Context, targetURL string, authToken string, insecure bool, timeout time.Duration) (*RawCard, error) {
	base := normalizeBaseURL(targetURL)

	transport := &http.Transport{}
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects (max 5)")
			}
			return nil
		},
	}

	card, err := fetchCard(ctx, client, base+v10Path, authToken, "v1.0")
	if err != nil {
		if fe, ok := err.(*FetchError); ok && fe.StatusCode == 404 {
			card, err = fetchCard(ctx, client, base+v030Path, authToken, "v0.3.0")
			if err != nil {
				return nil, fmt.Errorf("agent card not found at %s: %w", base, err)
			}
		} else {
			return nil, err
		}
	}

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

func fetchCard(
	ctx context.Context,
	client *http.Client,
	url string,
	authToken string,
	schemaVersion string,
) (*RawCard, error) {
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyLen+1))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", url, err)
	}
	if len(body) > maxBodyLen {
		return nil, fmt.Errorf("agent card from %s exceeds %d bytes", url, maxBodyLen)
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("parse JSON from %s: %w", url, err)
	}
	jsonValidationError := ""
	if err := validateRawCardJSON(body); err != nil {
		jsonValidationError = err.Error()
	}

	cardHash := common.HashSHA256(string(body))

	return &RawCard{
		Parsed:              parsed,
		Version:             detectVersionWithPathHint(parsed, schemaVersion),
		CardHash:            cardHash,
		JSONValidationError: jsonValidationError,
	}, nil
}

func validateRawCardJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > maxSignedDepth {
			return fmt.Errorf("JSON exceeds maximum depth %d", maxSignedDepth)
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("JSON object key is not a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
		}
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func normalizeBaseURL(rawURL string) string {
	return common.NormalizeA2ABaseURL(rawURL)
}

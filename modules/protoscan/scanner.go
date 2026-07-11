// Package protoscan implements the v0.3 Discover action — content-driven
// detection of MCP servers and A2A agents on a network. Unlike
// modules/networkscan (which is a TCP port-sweeper feeding fingerprint
// dispatch on AI-service ports), protoscan probes per-protocol shapes:
//
//   - MCP discovery: HTTP POST a JSON-RPC `initialize` request and check
//     the response for the canonical {"jsonrpc":"2.0","id":1,"result":
//     {"capabilities":{...},"serverInfo":{...}}} envelope.
//
//   - A2A discovery: HTTP GET /.well-known/agent-card.json (v0.3.0+) and
//     fall back to /.well-known/agent.json (legacy). The response is JSON
//     against the A2A agent-card shape; protoscan only does shape
//     validation (presence of "name" + ("url" OR "supportedInterfaces")).
//     The full A2A collector fetches and parses cards downstream.
//
// Both modes share modules/networkscan/expand.go for CIDR safety gates.
//
// protoscan is intentionally lean — it emits raw MCPServer / A2AAgent
// nodes with the bare minimum properties to make them queryable, and
// records the fact-of-discovery on the node via discovered_via. The full
// MCP enumeration (modules/mcp) and A2A card fetch (modules/a2a) consume
// the discovered endpoints in subsequent runs to produce the rich
// per-server / per-agent property surface.
package protoscan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adithyan-ak/agenthound/modules/networkscan"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// DefaultMCPPorts and DefaultA2APorts are the HTTP ports we probe for
// each protocol. MCP servers commonly listen on 3000/8080/8000 (the
// JSON-RPC HTTP transport); A2A agents on 80/443 of well-known
// hostnames OR on the same alt-HTTP ports.
//
// These do NOT overlap perfectly with networkscan.DefaultPorts because
// the fingerprinter port set is AI-service-specific (Ollama on 11434,
// LiteLLM on 4000) — MCP and A2A are protocol-discovery surfaces and
// land on the generic web ports.
var (
	DefaultMCPPorts = []int{3000, 8000, 8080, 8443}
	DefaultA2APorts = []int{80, 443, 3000, 8080}
)

const (
	DefaultConcurrency  = 50
	DefaultProbeTimeout = 5 * time.Second

	// MaxConcurrency caps the worker pool so an absurd concurrency value can't
	// spawn a runaway number of goroutines / HTTP connections.
	MaxConcurrency = 4096
)

// Scanner discovers MCP servers and A2A agents on a network. It conforms to
// action.Scanner (see the compile-time assertion at the bottom of this file)
// and is constructed directly by the `discover` CLI (collector/cli/discover.go)
// per mode — it is not registered in sdk/module.
type Scanner struct {
	Mode        Mode
	MCPPorts    []int
	A2APorts    []int
	Concurrency int
	Timeout     time.Duration
	Insecure    bool
	ExpandOpts  networkscan.ExpandOptions

	// Progress, if non-nil, is called periodically with the number of
	// completed probes and the total probe count (hosts × protocol ports).
	// It is invoked from a single dedicated goroutine on a fixed cadence,
	// plus once at the end, so implementations may render without locking.
	Progress func(done, total int)

	httpClient *http.Client
}

// Mode selects MCP, A2A, or both.
type Mode int

const (
	ModeBoth Mode = iota
	ModeMCP
	ModeA2A
)

// Scan expands the spec, probes each host's configured ports, and emits
// one Target per discovered MCP / A2A endpoint. Targets carry:
//
//	"kind"          = "host"
//	"address"       = "<host>:<port>"
//	"meta.protocol" = "mcp" or "a2a"
//	"meta.scheme"   = "http" or "https"
//	"meta.url"      = full base URL
func (s *Scanner) Scan(ctx context.Context, spec string) ([]action.Target, error) {
	hosts, err := networkscan.Expand(spec, s.ExpandOpts)
	if err != nil {
		return nil, err
	}
	if s.Concurrency <= 0 {
		s.Concurrency = DefaultConcurrency
	}
	if s.Concurrency > MaxConcurrency {
		s.Concurrency = MaxConcurrency
	}
	if s.Timeout <= 0 {
		s.Timeout = DefaultProbeTimeout
	}
	s.httpClient = &http.Client{
		Timeout: s.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: s.Insecure}, //nolint:gosec
			DialContext: (&net.Dialer{
				Timeout: s.Timeout,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	wantMCP := s.Mode == ModeBoth || s.Mode == ModeMCP
	wantA2A := s.Mode == ModeBoth || s.Mode == ModeA2A

	mcpPorts := s.MCPPorts
	if len(mcpPorts) == 0 {
		mcpPorts = DefaultMCPPorts
	}
	a2aPorts := s.A2APorts
	if len(a2aPorts) == 0 {
		a2aPorts = DefaultA2APorts
	}

	type job struct {
		host     string
		port     int
		protocol string
	}
	var jobs []job
	for _, h := range hosts {
		if wantMCP {
			for _, p := range mcpPorts {
				jobs = append(jobs, job{h, p, "mcp"})
			}
		}
		if wantA2A {
			for _, p := range a2aPorts {
				jobs = append(jobs, job{h, p, "a2a"})
			}
		}
	}

	results := make([]action.Target, 0, len(hosts))
	var mu sync.Mutex

	// Progress accounting: workers bump completed after each probe; a single
	// reporter goroutine samples it on a fixed cadence so rendering never
	// contends with the worker pool. Guarded so a nil Progress costs nothing.
	total := len(jobs)
	var completed atomic.Int64
	var stopReporter, reporterDone chan struct{}
	if s.Progress != nil && total > 0 {
		stopReporter = make(chan struct{})
		reporterDone = make(chan struct{})
		go func() {
			defer close(reporterDone)
			ticker := time.NewTicker(150 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-stopReporter:
					return
				case <-ticker.C:
					s.Progress(int(completed.Load()), total)
				}
			}
		}()
	}

	jobCh := make(chan job)
	var wg sync.WaitGroup
	for i := 0; i < s.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				if ctx.Err() != nil {
					return
				}
				if t, ok := s.probeOne(ctx, j.host, j.port, j.protocol); ok {
					mu.Lock()
					results = append(results, t)
					mu.Unlock()
				}
				completed.Add(1)
			}
		}()
	}
	cancelled := false
dispatch:
	for _, j := range jobs {
		select {
		case <-ctx.Done():
			cancelled = true
			break dispatch
		case jobCh <- j:
		}
	}
	close(jobCh)
	wg.Wait()

	// Stop the reporter and emit one final sample. Receiving on reporterDone
	// guarantees the ticker goroutine has returned, so this last call can
	// never race with it.
	if s.Progress != nil && total > 0 {
		close(stopReporter)
		<-reporterDone
		s.Progress(int(completed.Load()), total)
	}

	if cancelled {
		return results, ctx.Err()
	}
	return results, nil
}

// probeOne issues the protocol-specific probe against host:port. Returns
// (target, true) on a positive match. Network errors and protocol-shape
// mismatches both produce (zero, false).
func (s *Scanner) probeOne(ctx context.Context, host string, port int, protocol string) (action.Target, bool) {
	// Try HTTPS first when port suggests it (443/8443), else HTTP.
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	switch protocol {
	case "mcp":
		if matchedPath, ok := s.probeMCP(ctx, baseURL); ok {
			// Preserve the matched path so the emitted MCPServer endpoint
			// (and thus its deterministic ID) matches what the mcp/config
			// collectors hash via ingest.ComputeMCPServerID. Trim a lone
			// trailing slash so a root ("/") match canonicalizes to the
			// path-less host:port form those collectors use for a bare URL;
			// "/mcp" is left intact. We only probe "/" and "/mcp", so the
			// trim can never strip a real sub-path.
			endpoint := strings.TrimSuffix(strings.TrimRight(baseURL, "/")+matchedPath, "/")
			return action.Target{
				Kind:    "host",
				Address: fmt.Sprintf("%s:%d", host, port),
				Meta: map[string]string{
					"protocol": "mcp",
					"scheme":   scheme,
					"url":      endpoint,
				},
			}, true
		}
	case "a2a":
		card, ok := s.probeA2A(ctx, baseURL)
		if !ok {
			return action.Target{}, false
		}
		return action.Target{
			Kind:    "host",
			Address: fmt.Sprintf("%s:%d", host, port),
			Meta: map[string]string{
				"protocol":       "a2a",
				"scheme":         scheme,
				"url":            baseURL,
				"agent_card_url": card,
			},
		}, true
	}
	return action.Target{}, false
}

// probeMCP POSTs a JSON-RPC initialize at "/" and at "/mcp" (the two
// most-common path conventions) and, on a canonical
// {"jsonrpc":"2.0","id":1,"result":{...}} response shape, returns the
// matched path and true. Returns ("", false) when no path matches.
func (s *Scanner) probeMCP(ctx context.Context, baseURL string) (string, bool) {
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "agenthound-protoscan",
				"version": "0.3.0-dev",
			},
		},
	})
	for _, path := range []string{"/", "/mcp"} {
		url := strings.TrimRight(baseURL, "/") + path
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		// Streamable HTTP MCP servers require BOTH media types in Accept and
		// may 406 otherwise; advertise both so spec-strict servers respond.
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		ctype := resp.Header.Get("Content-Type")
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		// A Streamable HTTP server may frame the initialize response as a single
		// SSE event (Content-Type: text/event-stream) rather than raw JSON;
		// pull the data payload out so the shape match works for both forms.
		if strings.Contains(ctype, "text/event-stream") {
			body = extractSSEData(body)
		}
		// Lenient JSON-RPC initialize response shape.
		var parsed struct {
			JSONRPC string `json:"jsonrpc"`
			ID      any    `json:"id"`
			Result  *struct {
				ProtocolVersion string         `json:"protocolVersion"`
				ServerInfo      map[string]any `json:"serverInfo"`
				Capabilities    map[string]any `json:"capabilities"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			continue
		}
		if parsed.JSONRPC == "2.0" && parsed.Result != nil &&
			(parsed.Result.ServerInfo != nil || parsed.Result.Capabilities != nil) {
			return path, true
		}
	}
	return "", false
}

// extractSSEData concatenates the `data:` field values from an SSE event
// stream body into a single byte slice. MCP's Streamable HTTP transport may
// frame the JSON-RPC initialize response as one SSE event; we only need the
// data payload to shape-match it. Returns the raw body unchanged if it
// contains no data lines (so a non-SSE body still flows to json.Unmarshal,
// which will then fail cleanly).
func extractSSEData(body []byte) []byte {
	var buf bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	found := false
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		found = true
		buf.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
	}
	if !found {
		return body
	}
	return buf.Bytes()
}

// probeA2A GETs /.well-known/agent-card.json and (on 404) the legacy
// /.well-known/agent.json. Returns the card URL on a positive match.
func (s *Scanner) probeA2A(ctx context.Context, baseURL string) (string, bool) {
	for _, path := range []string{"/.well-known/agent-card.json", "/.well-known/agent.json"} {
		url := strings.TrimRight(baseURL, "/") + path
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		// Lenient agent-card shape: must have "name" AND ("url" OR
		// "supportedInterfaces"). The full collector validates further.
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			continue
		}
		name, _ := parsed["name"].(string)
		_, hasURL := parsed["url"].(string)
		_, hasIfaces := parsed["supportedInterfaces"].([]any)
		if name != "" && (hasURL || hasIfaces) {
			return url, true
		}
	}
	return "", false
}

// EmitDiscoveryNodes turns the Scanner's positive matches into ingest
// payload. Called by the CLI after Scan() returns. The CLI passes the
// final ingest envelope through agenthound-server ingest, which writes
// :MCPServer and :A2AAgent nodes deterministically.
func EmitDiscoveryNodes(targets []action.Target) ingest.GraphData {
	var out ingest.GraphData
	for _, t := range targets {
		switch t.Meta["protocol"] {
		case "mcp":
			// Use the canonical MCPServer ID helper (full path-bearing URL)
			// so protoscan-discovered servers merge with the mcp/config
			// collectors at the documented merge point. t.Meta["url"] already
			// carries the matched, trailing-slash-trimmed endpoint.
			id := ingest.ComputeMCPServerID("http", t.Meta["url"])
			out.Nodes = append(out.Nodes, ingest.Node{
				ID:    id,
				Kinds: []string{"MCPServer"},
				Properties: map[string]any{
					"objectid":       id,
					"endpoint":       t.Meta["url"],
					"transport":      "http",
					"discovered_via": "protoscan",
					"protocol":       "mcp",
					"auth_method":    string(common.AuthUnknown),
					"auth_assurance": string(common.AuthAssuranceUnknown),
					"auth_evidence":  common.AuthEvidenceUnknown,
				},
			})
		case "a2a":
			cardURL := t.Meta["agent_card_url"]
			if cardURL == "" {
				cardURL = t.Meta["url"]
			}
			idInput := common.NormalizeA2ABaseURL(cardURL)
			id := ingest.ComputeNodeID("A2AAgent", idInput)
			out.Nodes = append(out.Nodes, ingest.Node{
				ID:    id,
				Kinds: []string{"A2AAgent"},
				Properties: map[string]any{
					"objectid":                      id,
					"agent_card_url":                cardURL,
					"endpoint":                      idInput,
					"discovered_via":                "protoscan",
					"protocol":                      "a2a",
					"auth_method":                   string(common.AuthUnknown),
					"auth_assurance":                string(common.AuthAssuranceUnknown),
					"auth_evidence":                 common.AuthEvidenceUnknown,
					"signature_verification_status": "unknown",
				},
			})
		}
	}
	return out
}

var _ action.Scanner = (*Scanner)(nil)

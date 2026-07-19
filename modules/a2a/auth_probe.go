package a2a

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/common"
)

const (
	A2AAuthProbeMethodGetTaskNonexistent      = "get_task_nonexistent"
	A2AAuthProbeStatusAnonymousProtocolAccess = "anonymous_protocol_access"
	A2AAuthProbeStatusAuthenticationRequired  = "authentication_required"
	A2AAuthProbeStatusUnknown                 = "unknown"

	defaultA2AAuthProbeTimeout    = 5 * time.Second
	maxA2AAuthProbeResponseBytes  = int64(64 * 1024)
	a2aVersionHeader              = "A2A-Version"
	a2aTaskNotFoundCode           = -32001
	a2aV030CompatTaskNotFoundCode = -32603
	a2aTaskNotFoundMessage        = "Task not found"
	a2aTaskNotFoundReason         = "TASK_NOT_FOUND"
	a2aTaskNotFoundDomain         = "a2a-protocol.org"
	a2aErrorInfoType              = "type.googleapis.com/google.rpc.ErrorInfo"
)

// AuthProbeResult is deliberately limited to fixed categorical values. It
// never retains request IDs, target URLs, response bodies, or transport error
// strings, keeping scan artifacts deterministic and safe to share.
type AuthProbeResult struct {
	Method string
	Status string
	Detail string
}

type a2aProbeDialect uint8

const (
	a2aProbeDialectUnknown a2aProbeDialect = iota
	a2aProbeDialectV030
	a2aProbeDialectV1
)

type a2aProbeEndpoint struct {
	key           string
	requestURL    string
	origin        string
	dialect       a2aProbeDialect
	versionHeader string
}

type a2aAuthProbePlan struct {
	endpoint   a2aProbeEndpoint
	authorized bool
	cards      []*AgentCardData
	result     AuthProbeResult
}

type a2aJSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type a2aJSONRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      json.RawMessage  `json:"id"`
	Result  json.RawMessage  `json:"result"`
	Error   *a2aJSONRPCError `json:"error"`
}

type a2aErrorInfo struct {
	Type   string `json:"@type"`
	Reason string `json:"reason"`
	Domain string `json:"domain"`
}

// applyA2AAuthProbes plans probes only after every card has been parsed. The
// canonical protocol endpoint is the deduplication key, so multiple discovery
// aliases for one logical endpoint receive exactly the same observation.
//
// A card is untrusted input. An endpoint is eligible only when at least one of
// its discovery aliases has the exact same HTTP origin. This prevents the card
// from expanding the operator-authorized collection scope into an SSRF probe.
func applyA2AAuthProbes(
	ctx context.Context,
	results []a2aCardResult,
	insecure bool,
	timeout time.Duration,
	concurrency int,
) {
	plansByEndpoint := make(map[string]*a2aAuthProbePlan)
	for index := range results {
		result := &results[index]
		if result.err != nil || result.card == nil {
			continue
		}
		endpoint, detail, ok := preferredA2AProbeEndpoint(result.card)
		if !ok {
			result.card.AuthProbe = unknownA2AAuthProbe(detail)
			continue
		}

		plan := plansByEndpoint[endpoint.key]
		if plan == nil {
			plan = &a2aAuthProbePlan{endpoint: endpoint}
			plansByEndpoint[endpoint.key] = plan
		} else if preferA2AProbeEndpoint(endpoint, plan.endpoint) {
			// Conflicting aliases for the same endpoint cannot make output depend
			// on target order. Prefer v1, then the lexically first version header.
			plan.endpoint = endpoint
		}
		plan.cards = append(plan.cards, result.card)
		if discoveryOrigin, valid := canonicalHTTPOrigin(normalizeBaseURL(result.url)); valid && discoveryOrigin == endpoint.origin {
			plan.authorized = true
		}
	}

	keys := make([]string, 0, len(plansByEndpoint))
	for key := range plansByEndpoint {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	if concurrency <= 0 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, key := range keys {
		plan := plansByEndpoint[key]
		if !plan.authorized {
			plan.result = unknownA2AAuthProbe("cross_origin_interface")
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			plan.result = observeA2AAuth(ctx, plan.endpoint, insecure, timeout)
		}()
	}
	wg.Wait()

	for _, key := range keys {
		plan := plansByEndpoint[key]
		for _, card := range plan.cards {
			card.AuthProbe = plan.result
		}
	}
}

func preferredA2AProbeEndpoint(card *AgentCardData) (a2aProbeEndpoint, string, bool) {
	if card == nil || len(card.Interfaces) == 0 {
		return a2aProbeEndpoint{}, "no_preferred_interface", false
	}
	preferred := card.Interfaces[0]
	if !preferred.Preferred {
		return a2aProbeEndpoint{}, "no_preferred_interface", false
	}
	if !preferred.Conformant {
		return a2aProbeEndpoint{}, "nonconformant_preferred_interface", false
	}
	if !strings.EqualFold(strings.TrimSpace(preferred.ProtocolBinding), "JSONRPC") {
		return a2aProbeEndpoint{}, "unsupported_protocol_binding", false
	}
	parsedInterface, err := url.Parse(strings.TrimSpace(preferred.URL))
	if err == nil && (parsedInterface.RawQuery != "" || parsedInterface.ForceQuery) {
		// Query bytes may be credentials regardless of their key name. Sending
		// them would make the supposedly anonymous probe authenticated.
		return a2aProbeEndpoint{}, "query_interface_not_probeable", false
	}

	dialect, versionHeader, ok := a2aAuthProbeDialect(preferred.ProtocolVersion)
	if !ok {
		return a2aProbeEndpoint{}, "unsupported_protocol_version", false
	}
	requestURL, origin, ok := canonicalHTTPProbeURL(preferred.URL)
	if !ok {
		return a2aProbeEndpoint{}, "invalid_preferred_interface_url", false
	}
	return a2aProbeEndpoint{
		key:           requestURL,
		requestURL:    requestURL,
		origin:        origin,
		dialect:       dialect,
		versionHeader: versionHeader,
	}, "", true
}

func a2aAuthProbeDialect(rawVersion string) (a2aProbeDialect, string, bool) {
	version := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(rawVersion), "v"))
	switch {
	case version == "1" || strings.HasPrefix(version, "1."):
		return a2aProbeDialectV1, version, true
	case version == "0.3" || strings.HasPrefix(version, "0.3."):
		return a2aProbeDialectV030, "", true
	default:
		return a2aProbeDialectUnknown, "", false
	}
}

func preferA2AProbeEndpoint(candidate, current a2aProbeEndpoint) bool {
	if candidate.dialect != current.dialect {
		return candidate.dialect > current.dialect
	}
	return candidate.versionHeader < current.versionHeader
}

func canonicalHTTPProbeURL(raw string) (string, string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !parsed.IsAbs() || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery {
		return "", "", false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", false
	}
	hostname := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", false
	}
	origin := scheme + "://" + net.JoinHostPort(hostname, port)

	parsed.Scheme = scheme
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		if strings.Contains(hostname, ":") {
			parsed.Host = "[" + hostname + "]"
		} else {
			parsed.Host = hostname
		}
	} else {
		parsed.Host = net.JoinHostPort(hostname, port)
	}
	if parsed.Path == "" {
		parsed.Path = "/"
		parsed.RawPath = ""
	}
	return parsed.String(), origin, true
}

func canonicalHTTPOrigin(raw string) (string, bool) {
	_, origin, ok := canonicalHTTPProbeURL(raw)
	return origin, ok
}

func observeA2AAuth(
	ctx context.Context,
	endpoint a2aProbeEndpoint,
	insecure bool,
	timeout time.Duration,
) AuthProbeResult {
	requestID, err := newA2AProbeID()
	if err != nil {
		return unknownA2AAuthProbe("random_id_generation_failed")
	}
	taskID, err := newA2AProbeID()
	if err != nil {
		return unknownA2AAuthProbe("random_id_generation_failed")
	}
	method := "tasks/get"
	if endpoint.dialect == a2aProbeDialectV1 {
		method = "GetTask"
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  method,
		"params":  map[string]any{"id": taskID},
	})
	if err != nil {
		return unknownA2AAuthProbe("request_encoding_failed")
	}

	probeTimeout := timeout
	if probeTimeout <= 0 || probeTimeout > defaultA2AAuthProbeTimeout {
		probeTimeout = defaultA2AAuthProbeTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(
		probeCtx,
		http.MethodPost,
		endpoint.requestURL,
		bytes.NewReader(body),
	)
	if err != nil {
		return unknownA2AAuthProbe("request_creation_failed")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if endpoint.dialect == a2aProbeDialectV1 {
		req.Header.Set(a2aVersionHeader, endpoint.versionHeader)
	}

	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return unknownA2AAuthProbe("transport_unavailable")
	}
	transport := baseTransport.Clone()
	if insecure {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		}
		transport.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return unknownA2AAuthProbe(a2aProbeTransportDetail(probeCtx, err))
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return protectedA2AAuthProbe("http_unauthorized")
	case http.StatusForbidden:
		return protectedA2AAuthProbe("http_forbidden")
	case http.StatusOK:
		// Continue with the exact JSON-RPC witness checks below.
	default:
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return unknownA2AAuthProbe("redirect_response")
		}
		return unknownA2AAuthProbe("unexpected_http_status")
	}

	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return unknownA2AAuthProbe("non_json_response")
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxA2AAuthProbeResponseBytes+1))
	if err != nil {
		return unknownA2AAuthProbe(a2aProbeTransportDetail(probeCtx, err))
	}
	if int64(len(responseBody)) > maxA2AAuthProbeResponseBytes {
		return unknownA2AAuthProbe("response_too_large")
	}
	if err := validateRawCardJSON(responseBody); err != nil {
		return unknownA2AAuthProbe("malformed_jsonrpc_response")
	}
	var rpcResponse a2aJSONRPCResponse
	if err := json.Unmarshal(responseBody, &rpcResponse); err != nil {
		return unknownA2AAuthProbe("malformed_jsonrpc_response")
	}
	if rpcResponse.JSONRPC != "2.0" || rpcResponse.Error == nil || len(rpcResponse.Result) != 0 {
		return unknownA2AAuthProbe("unexpected_jsonrpc_response")
	}
	var responseID string
	if err := json.Unmarshal(rpcResponse.ID, &responseID); err != nil || responseID != requestID {
		return unknownA2AAuthProbe("response_id_mismatch")
	}
	if !isNarrowTaskNotFound(endpoint.dialect, rpcResponse.Error) {
		return unknownA2AAuthProbe("non_task_not_found_error")
	}
	if endpoint.dialect == a2aProbeDialectV1 {
		return anonymousA2AAuthProbe("task_not_found_v1")
	}
	return anonymousA2AAuthProbe("task_not_found_v0_3")
}

func newA2AProbeID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func isNarrowTaskNotFound(dialect a2aProbeDialect, rpcError *a2aJSONRPCError) bool {
	if rpcError == nil || rpcError.Message != a2aTaskNotFoundMessage {
		return false
	}
	if dialect == a2aProbeDialectV030 {
		if rpcError.Code == a2aV030CompatTaskNotFoundCode && jsonNullOrAbsent(rpcError.Data) {
			return true
		}
		if rpcError.Code != a2aTaskNotFoundCode {
			return false
		}
		return jsonNullOrAbsent(rpcError.Data) || hasExactA2ATaskNotFoundInfo(rpcError.Data)
	}
	return dialect == a2aProbeDialectV1 &&
		rpcError.Code == a2aTaskNotFoundCode &&
		hasExactA2ATaskNotFoundInfo(rpcError.Data)
}

func hasExactA2ATaskNotFoundInfo(raw json.RawMessage) bool {
	var details []a2aErrorInfo
	if len(raw) == 0 || json.Unmarshal(raw, &details) != nil || len(details) == 0 {
		return false
	}
	for _, detail := range details {
		if detail.Type == a2aErrorInfoType &&
			detail.Reason == a2aTaskNotFoundReason &&
			detail.Domain == a2aTaskNotFoundDomain {
			return true
		}
	}
	return false
}

func jsonNullOrAbsent(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func a2aProbeTransportDetail(ctx context.Context, err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return "context_canceled"
	default:
		return "transport_error"
	}
}

func unknownA2AAuthProbe(detail string) AuthProbeResult {
	return AuthProbeResult{
		Method: A2AAuthProbeMethodGetTaskNonexistent,
		Status: A2AAuthProbeStatusUnknown,
		Detail: detail,
	}
}

func protectedA2AAuthProbe(detail string) AuthProbeResult {
	return AuthProbeResult{
		Method: A2AAuthProbeMethodGetTaskNonexistent,
		Status: A2AAuthProbeStatusAuthenticationRequired,
		Detail: detail,
	}
}

func anonymousA2AAuthProbe(detail string) AuthProbeResult {
	return AuthProbeResult{
		Method: A2AAuthProbeMethodGetTaskNonexistent,
		Status: A2AAuthProbeStatusAnonymousProtocolAccess,
		Detail: detail,
	}
}

func applyAuthProbeProperties(properties map[string]any, result AuthProbeResult) {
	if result.Method == "" {
		return
	}
	properties["auth_probe_method"] = result.Method
	properties["auth_probe_status"] = result.Status
	if result.Detail != "" {
		properties["auth_probe_detail"] = result.Detail
	}
	if result.Method != A2AAuthProbeMethodGetTaskNonexistent ||
		result.Status != A2AAuthProbeStatusAnonymousProtocolAccess ||
		(result.Detail != "task_not_found_v1" && result.Detail != "task_not_found_v0_3") {
		return
	}
	properties["observed_auth_method"] = string(common.AuthNone)
	properties["observed_auth_assurance"] = string(common.AuthAssuranceUnauthenticated)
	properties["observed_auth_evidence"] = common.AuthEvidenceAnonymousProbeSucceeded
}

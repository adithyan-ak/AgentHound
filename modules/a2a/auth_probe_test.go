package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

type capturedA2AProbeRequest struct {
	Method        string
	Authorization string
	Cookie        string
	APIKey        string
	Version       string
	JSONRPC       string
	RequestID     string
	RPCMethod     string
	TaskID        string
}

func captureA2AProbeRequest(r *http.Request) (capturedA2AProbeRequest, error) {
	var payload struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Method  string `json:"method"`
		Params  struct {
			ID string `json:"id"`
		} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		return capturedA2AProbeRequest{}, err
	}
	return capturedA2AProbeRequest{
		Method:        r.Method,
		Authorization: r.Header.Get("Authorization"),
		Cookie:        r.Header.Get("Cookie"),
		APIKey:        r.Header.Get("X-API-Key"),
		Version:       r.Header.Get(a2aVersionHeader),
		JSONRPC:       payload.JSONRPC,
		RequestID:     payload.ID,
		RPCMethod:     payload.Method,
		TaskID:        payload.Params.ID,
	}, nil
}

func writeV1TaskNotFound(w http.ResponseWriter, requestID string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      requestID,
		"error": map[string]any{
			"code":    a2aTaskNotFoundCode,
			"message": a2aTaskNotFoundMessage,
			"data": []any{map[string]any{
				"@type":    a2aErrorInfoType,
				"reason":   a2aTaskNotFoundReason,
				"domain":   a2aTaskNotFoundDomain,
				"metadata": map[string]any{},
			}},
		},
	})
}

func writeV030TaskNotFound(w http.ResponseWriter, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      requestID,
		"error": map[string]any{
			"code":    a2aV030CompatTaskNotFoundCode,
			"message": a2aTaskNotFoundMessage,
			"data":    nil,
		},
	})
}

func testA2AProbeEndpoint(rawURL string, dialect a2aProbeDialect) a2aProbeEndpoint {
	requestURL, origin, ok := canonicalHTTPProbeURL(rawURL)
	if !ok {
		panic("invalid test probe URL")
	}
	version := ""
	if dialect == a2aProbeDialectV1 {
		version = "1.0"
	}
	return a2aProbeEndpoint{
		key:           requestURL,
		requestURL:    requestURL,
		origin:        origin,
		dialect:       dialect,
		versionHeader: version,
	}
}

func TestObserveA2AAuthUsesOnlyReadOnlyV1GetTaskWithoutCredentials(t *testing.T) {
	var captured capturedA2AProbeRequest
	var captureErr error
	var mutationCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, captureErr = captureA2AProbeRequest(r)
		if captureErr != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if captured.RPCMethod != "GetTask" {
			mutationCalls.Add(1)
		}
		writeV1TaskNotFound(w, captured.RequestID)
	}))
	t.Cleanup(server.Close)

	result := observeA2AAuth(
		context.Background(),
		testA2AProbeEndpoint(server.URL, a2aProbeDialectV1),
		false,
		time.Second,
	)
	if captureErr != nil {
		t.Fatalf("decode request: %v", captureErr)
	}
	if result != anonymousA2AAuthProbe("task_not_found_v1") {
		t.Fatalf("result = %+v", result)
	}
	if captured.Method != http.MethodPost || captured.JSONRPC != "2.0" ||
		captured.RPCMethod != "GetTask" || captured.Version != "1.0" {
		t.Fatalf("request = %+v", captured)
	}
	if captured.Authorization != "" || captured.Cookie != "" || captured.APIKey != "" {
		t.Fatalf("anonymous probe forwarded credentials: %+v", captured)
	}
	idPattern := regexp.MustCompile(`^[0-9a-f]{32}$`)
	if !idPattern.MatchString(captured.RequestID) || !idPattern.MatchString(captured.TaskID) ||
		captured.RequestID == captured.TaskID {
		t.Fatalf("probe IDs are not independent 128-bit random values: %+v", captured)
	}
	if mutationCalls.Load() != 0 {
		t.Fatalf("probe reached a mutation method %d times", mutationCalls.Load())
	}
}

func TestObserveA2AAuthUsesV030TasksGetWithoutVersionHeader(t *testing.T) {
	var captured capturedA2AProbeRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		captured, err = captureA2AProbeRequest(r)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		writeV030TaskNotFound(w, captured.RequestID)
	}))
	t.Cleanup(server.Close)

	result := observeA2AAuth(
		context.Background(),
		testA2AProbeEndpoint(server.URL, a2aProbeDialectV030),
		false,
		time.Second,
	)
	if result != anonymousA2AAuthProbe("task_not_found_v0_3") {
		t.Fatalf("result = %+v", result)
	}
	if captured.RPCMethod != "tasks/get" || captured.Version != "" {
		t.Fatalf("v0.3 request = %+v", captured)
	}
}

func TestObserveA2AAuthClassifiesOnlyExactTaskNotFound(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		response    func(string) string
		want        AuthProbeResult
	}{
		{
			name: "unauthorized", statusCode: http.StatusUnauthorized,
			want: protectedA2AAuthProbe("http_unauthorized"),
		},
		{
			name: "forbidden", statusCode: http.StatusForbidden,
			want: protectedA2AAuthProbe("http_forbidden"),
		},
		{
			name: "mismatched response id", statusCode: http.StatusOK, contentType: "application/json",
			response: func(string) string {
				return `{"jsonrpc":"2.0","id":"different","error":{"code":-32001,"message":"Task not found","data":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"TASK_NOT_FOUND","domain":"a2a-protocol.org"}]}}`
			},
			want: unknownA2AAuthProbe("response_id_mismatch"),
		},
		{
			name: "method not found", statusCode: http.StatusOK, contentType: "application/json",
			response: func(id string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"error":{"code":-32601,"message":"Method not found"}}`, id)
			},
			want: unknownA2AAuthProbe("non_task_not_found_error"),
		},
		{
			name: "version not supported", statusCode: http.StatusOK, contentType: "application/json",
			response: func(id string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"error":{"code":-32009,"message":"Version not supported"}}`, id)
			},
			want: unknownA2AAuthProbe("non_task_not_found_error"),
		},
		{
			name: "generic internal error", statusCode: http.StatusOK, contentType: "application/json",
			response: func(id string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"error":{"code":-32603,"message":"Internal error"}}`, id)
			},
			want: unknownA2AAuthProbe("non_task_not_found_error"),
		},
		{
			name: "task code without structured reason", statusCode: http.StatusOK, contentType: "application/json",
			response: func(id string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"error":{"code":-32001,"message":"Task not found","data":null}}`, id)
			},
			want: unknownA2AAuthProbe("non_task_not_found_error"),
		},
		{
			name: "wrong structured reason", statusCode: http.StatusOK, contentType: "application/json",
			response: func(id string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"error":{"code":-32001,"message":"Task not found","data":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"AUTHENTICATION_REQUIRED","domain":"a2a-protocol.org"}]}}`, id)
			},
			want: unknownA2AAuthProbe("non_task_not_found_error"),
		},
		{
			name: "result and error", statusCode: http.StatusOK, contentType: "application/json",
			response: func(id string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"result":null,"error":{"code":-32001,"message":"Task not found"}}`, id)
			},
			want: unknownA2AAuthProbe("unexpected_jsonrpc_response"),
		},
		{
			name: "malformed json", statusCode: http.StatusOK, contentType: "application/json",
			response: func(string) string { return `{"jsonrpc":` },
			want:     unknownA2AAuthProbe("malformed_jsonrpc_response"),
		},
		{
			name: "duplicate response id", statusCode: http.StatusOK, contentType: "application/json",
			response: func(id string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"id":%q,"error":{"code":-32001,"message":"Task not found"}}`, id, id)
			},
			want: unknownA2AAuthProbe("malformed_jsonrpc_response"),
		},
		{
			name: "html", statusCode: http.StatusOK, contentType: "text/html",
			response: func(string) string { return `<html>Task not found</html>` },
			want:     unknownA2AAuthProbe("non_json_response"),
		},
		{
			name: "oversize", statusCode: http.StatusOK, contentType: "application/json",
			response: func(string) string {
				return strings.Repeat(" ", int(maxA2AAuthProbeResponseBytes)+1)
			},
			want: unknownA2AAuthProbe("response_too_large"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured, err := captureA2AProbeRequest(r)
				if err != nil {
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}
				if test.contentType != "" {
					w.Header().Set("Content-Type", test.contentType)
				}
				status := test.statusCode
				if status == 0 {
					status = http.StatusOK
				}
				w.WriteHeader(status)
				if test.response != nil {
					_, _ = w.Write([]byte(test.response(captured.RequestID)))
				}
			}))
			t.Cleanup(server.Close)

			got := observeA2AAuth(
				context.Background(),
				testA2AProbeEndpoint(server.URL, a2aProbeDialectV1),
				false,
				time.Second,
			)
			if got != test.want {
				t.Fatalf("result = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestObserveA2AAuthRejectsRedirectAndBoundsTimeout(t *testing.T) {
	var redirectedCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedCalls.Add(1)
		writeV1TaskNotFound(w, "should-not-be-reached")
	}))
	t.Cleanup(target.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)
	got := observeA2AAuth(
		context.Background(),
		testA2AProbeEndpoint(redirector.URL, a2aProbeDialectV1),
		false,
		time.Second,
	)
	if got != unknownA2AAuthProbe("redirect_response") || redirectedCalls.Load() != 0 {
		t.Fatalf("redirect result = %+v, redirected calls = %d", got, redirectedCalls.Load())
	}

	timeoutServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(timeoutServer.Close)
	started := time.Now()
	got = observeA2AAuth(
		context.Background(),
		testA2AProbeEndpoint(timeoutServer.URL, a2aProbeDialectV1),
		false,
		25*time.Millisecond,
	)
	if got != unknownA2AAuthProbe("timeout") {
		t.Fatalf("timeout result = %+v", got)
	}
	if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
		t.Fatalf("probe timeout was not bounded: %v", elapsed)
	}
}

func TestCollectorPreservesDeclaredAuthAndNeverForwardsOperatorAuthToProbe(t *testing.T) {
	var server *httptest.Server
	var cardAuthorization string
	var probeAuthorization string
	var probeCalls atomic.Int32
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			cardAuthorization = r.Header.Get("Authorization")
			card := validV10Card()
			card["supportedInterfaces"] = []any{map[string]any{
				"url": server.URL, "protocolBinding": "JSONRPC", "protocolVersion": "1.0",
			}}
			card["securitySchemes"] = map[string]any{
				"bearer": map[string]any{
					"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer"},
				},
			}
			card["securityRequirements"] = []any{map[string]any{
				"schemes": map[string]any{"bearer": map[string]any{"list": []any{}}},
			}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(card)
			return
		}
		probeCalls.Add(1)
		probeAuthorization = r.Header.Get("Authorization")
		captured, err := captureA2AProbeRequest(r)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		writeV1TaskNotFound(w, captured.RequestID)
	}))
	t.Cleanup(server.Close)

	data, err := NewA2ACollector(WithJWKSFetch(false)).Collect(
		context.Background(),
		collector.CollectOptions{
			TargetURL: server.URL,
			AuthToken: "operator-secret",
			ScanID:    "a2a-auth-observer",
		},
	)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if cardAuthorization != "Bearer operator-secret" {
		t.Fatalf("card request Authorization = %q", cardAuthorization)
	}
	if probeAuthorization != "" || probeCalls.Load() != 1 {
		t.Fatalf("probe Authorization = %q, calls = %d", probeAuthorization, probeCalls.Load())
	}
	agent := findA2AAgentNode(t, data)
	props := agent.Properties
	if props["auth_method"] != "bearer" ||
		props["auth_assurance"] != string(common.AuthAssuranceModerate) ||
		props["auth_evidence"] != common.AuthEvidenceDeclaredScheme {
		t.Fatalf("declared auth provenance was overwritten: %+v", props)
	}
	assertAnonymousA2AProbeProperties(t, props, "task_not_found_v1")

	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}
	if strings.Contains(string(encoded), "operator-secret") {
		t.Fatal("operator credential leaked into scan artifact")
	}
}

func TestCollectorDeduplicatesAliasProbeAndKeepsArtifactDeterministic(t *testing.T) {
	var server *httptest.Server
	var probeCalls atomic.Int32
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			card := validV10Card()
			card["supportedInterfaces"] = []any{map[string]any{
				"url": server.URL, "protocolBinding": "JSONRPC", "protocolVersion": "1.0",
			}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(card)
			return
		}
		probeCalls.Add(1)
		captured, err := captureA2AProbeRequest(r)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		writeV1TaskNotFound(w, captured.RequestID)
	}))
	t.Cleanup(server.Close)

	collect := func(targets []string) *ingest.IngestData {
		t.Helper()
		data, err := NewA2ACollector(WithJWKSFetch(false)).Collect(
			context.Background(),
			collector.CollectOptions{TargetURLs: targets, ScanID: "stable-a2a-probe"},
		)
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		return data
	}
	forwardTargets := []string{server.URL + "/alias-b", server.URL + "/alias-a"}
	forward := collect(forwardTargets)
	if probeCalls.Load() != 1 {
		t.Fatalf("same protocol endpoint probed %d times, want 1", probeCalls.Load())
	}
	reversed := collect([]string{forwardTargets[1], forwardTargets[0]})
	if probeCalls.Load() != 2 {
		t.Fatalf("second collection did not issue exactly one probe: %d", probeCalls.Load())
	}

	for _, data := range []*ingest.IngestData{forward, reversed} {
		var agentProperties []map[string]any
		for _, node := range data.Graph.Nodes {
			if ingest.ConcreteNodeKind(node.Kinds) == "A2AAgent" {
				agentProperties = append(agentProperties, node.Properties)
			}
		}
		if len(agentProperties) != 2 || !reflect.DeepEqual(agentProperties[0], agentProperties[1]) {
			t.Fatalf("alias contributions disagree: %#v", agentProperties)
		}
		assertAnonymousA2AProbeProperties(t, agentProperties[0], "task_not_found_v1")
	}
	scrubA2AArtifactVolatile(forward)
	scrubA2AArtifactVolatile(reversed)
	if !reflect.DeepEqual(forward, reversed) {
		forwardJSON, _ := json.MarshalIndent(forward, "", "  ")
		reversedJSON, _ := json.MarshalIndent(reversed, "", "  ")
		t.Fatalf("random probe IDs or target order changed artifact:\n%s\n%s", forwardJSON, reversedJSON)
	}
}

func TestCollectorDoesNotProbeCrossOriginCardInterface(t *testing.T) {
	var crossOriginCalls atomic.Int32
	probeTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		crossOriginCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(probeTarget.Close)
	cardServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		card := validV10Card()
		card["supportedInterfaces"] = []any{map[string]any{
			"url": probeTarget.URL, "protocolBinding": "JSONRPC", "protocolVersion": "1.0",
		}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	}))
	t.Cleanup(cardServer.Close)

	data, err := NewA2ACollector(WithJWKSFetch(false)).Collect(
		context.Background(),
		collector.CollectOptions{TargetURL: cardServer.URL, ScanID: "cross-origin-card"},
	)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if crossOriginCalls.Load() != 0 {
		t.Fatalf("untrusted cross-origin endpoint received %d probe(s)", crossOriginCalls.Load())
	}
	props := findA2AAgentNode(t, data).Properties
	if props["auth_probe_method"] != A2AAuthProbeMethodGetTaskNonexistent ||
		props["auth_probe_status"] != A2AAuthProbeStatusUnknown ||
		props["auth_probe_detail"] != "cross_origin_interface" {
		t.Fatalf("cross-origin diagnostics = %+v", props)
	}
	assertNoObservedA2AAuth(t, props)
}

func TestCollectorDoesNotProbePreferredInterfaceWithQueryBytes(t *testing.T) {
	for _, suffix := range []string{"?tenant=one", "?"} {
		suffix := suffix
		t.Run(suffix, func(t *testing.T) {
			var server *httptest.Server
			var protocolCalls atomic.Int32
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					protocolCalls.Add(1)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				card := validV10Card()
				card["supportedInterfaces"] = []any{map[string]any{
					"url": server.URL + suffix, "protocolBinding": "JSONRPC", "protocolVersion": "1.0",
				}}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(card)
			}))
			t.Cleanup(server.Close)

			data, err := NewA2ACollector(WithJWKSFetch(false)).Collect(
				context.Background(),
				collector.CollectOptions{TargetURL: server.URL, ScanID: "query-interface"},
			)
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			if protocolCalls.Load() != 0 {
				t.Fatalf("query-bearing interface %q received %d probe(s)", suffix, protocolCalls.Load())
			}
			props := findA2AAgentNode(t, data).Properties
			if props["auth_probe_status"] != A2AAuthProbeStatusUnknown ||
				props["auth_probe_detail"] != "query_interface_not_probeable" {
				t.Fatalf("query-interface diagnostics for %q = %+v", suffix, props)
			}
			assertNoObservedA2AAuth(t, props)
		})
	}
}

func TestApplyAuthProbePropertiesOmitsObservedTupleForNonPositiveResults(t *testing.T) {
	for _, result := range []AuthProbeResult{
		protectedA2AAuthProbe("http_unauthorized"),
		unknownA2AAuthProbe("timeout"),
		{
			Method: A2AAuthProbeMethodGetTaskNonexistent,
			Status: A2AAuthProbeStatusAnonymousProtocolAccess,
			Detail: "non_task_not_found_error",
		},
	} {
		props := map[string]any{
			"auth_method":    "bearer",
			"auth_assurance": string(common.AuthAssuranceModerate),
			"auth_evidence":  common.AuthEvidenceDeclaredScheme,
		}
		applyAuthProbeProperties(props, result)
		assertNoObservedA2AAuth(t, props)
		if props["auth_method"] != "bearer" || props["auth_evidence"] != common.AuthEvidenceDeclaredScheme {
			t.Fatalf("raw declared tuple changed for %+v: %+v", result, props)
		}
	}
}

func TestCanonicalA2AProbeURLSafetyAndOrigin(t *testing.T) {
	canonical, origin, ok := canonicalHTTPProbeURL("HTTPS://EXAMPLE.test:443/a2a")
	if !ok || canonical != "https://example.test/a2a" ||
		origin != "https://example.test:443" {
		t.Fatalf("canonical URL = %q, origin = %q, ok = %v", canonical, origin, ok)
	}
	for _, raw := range []string{
		"https://user:secret@example.test/a2a",
		"https://example.test/a2a?tenant=one",
		"https://example.test/a2a#fragment",
		"ws://example.test/a2a",
		"https://example.test:not-a-port/a2a",
		"/relative/a2a",
	} {
		if _, _, ok := canonicalHTTPProbeURL(raw); ok {
			t.Fatalf("unsafe probe URL accepted: %q", raw)
		}
	}
}

func findA2AAgentNode(t *testing.T, data *ingest.IngestData) ingest.Node {
	t.Helper()
	for _, node := range data.Graph.Nodes {
		if ingest.ConcreteNodeKind(node.Kinds) == "A2AAgent" {
			return node
		}
	}
	t.Fatal("A2AAgent node not found")
	return ingest.Node{}
}

func assertAnonymousA2AProbeProperties(t *testing.T, props map[string]any, detail string) {
	t.Helper()
	if props["auth_probe_method"] != A2AAuthProbeMethodGetTaskNonexistent ||
		props["auth_probe_status"] != A2AAuthProbeStatusAnonymousProtocolAccess ||
		props["auth_probe_detail"] != detail ||
		props["observed_auth_method"] != string(common.AuthNone) ||
		props["observed_auth_assurance"] != string(common.AuthAssuranceUnauthenticated) ||
		props["observed_auth_evidence"] != common.AuthEvidenceAnonymousProbeSucceeded {
		t.Fatalf("anonymous probe properties = %+v", props)
	}
}

func assertNoObservedA2AAuth(t *testing.T, props map[string]any) {
	t.Helper()
	for _, key := range []string{
		"observed_auth_method", "observed_auth_assurance", "observed_auth_evidence",
	} {
		if _, present := props[key]; present {
			t.Fatalf("non-positive probe emitted %s: %+v", key, props)
		}
	}
}

func scrubA2AArtifactVolatile(data *ingest.IngestData) {
	data.Meta.Timestamp = ""
	for index := range data.Graph.Edges {
		delete(data.Graph.Edges[index].Properties, "last_seen")
	}
}

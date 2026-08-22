package litellmcollect

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/modules/litellmfp"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const fakeMasterKey = "sk-test-litellm-master-key-not-real"

// Deterministic hex digests standing in for LiteLLM's pre-hashed token
// column values. LiteLLM's proxy/utils.py hash_token() stores
// SHA-256(raw_key).hexdigest() as the token, so the strings the Collector
// receives are already 64 hex characters — never a raw sk-... value.
const (
	fakeHashedTokenA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd01"
	fakeHashedTokenB = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd02"
)

// stubLiteLLM is a configurable test server simulating LiteLLM responses.
// Each handler controls what /model/info and /key/list return; tests
// mix-and-match to exercise happy path, partial failure, and lenient
// parsing paths.
type stubLiteLLM struct {
	t              *testing.T
	modelInfoBody  string
	modelInfoCode  int
	keyListBody    string
	keyListCode    int
	requireBearer  bool
	seenMethods    []string
	seenAuthHeader []string
}

func newStub(t *testing.T) *stubLiteLLM {
	return &stubLiteLLM{
		t:             t,
		modelInfoCode: 200,
		keyListCode:   200,
		requireBearer: true,
	}
}

func (s *stubLiteLLM) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.seenMethods = append(s.seenMethods, r.Method)
		s.seenAuthHeader = append(s.seenAuthHeader, r.Header.Get("Authorization"))
		if r.URL.Path == "/health/liveliness" {
			_, _ = w.Write([]byte("I'm alive!"))
			return
		}
		if s.requireBearer && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/model/info":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(s.modelInfoCode)
			_, _ = w.Write([]byte(s.modelInfoBody))
		case "/key/list":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(s.keyListCode)
			_, _ = w.Write([]byte(s.keyListBody))
		default:
			w.WriteHeader(404)
		}
	}
}

// happyPathBody is a representative LiteLLM /model/info response carrying
// three providers. Shape is deliberately simplified vs. the real LiteLLM
// payload — the looter parses leniently, so unknown fields are fine.
const happyPathModelInfo = `{
  "data": [
    {
      "model_name": "gpt-4",
      "litellm_params": {"model": "openai/gpt-4", "api_base": "https://api.openai.com/v1"},
      "model_info": {"litellm_provider": "openai"}
    },
    {
      "model_name": "claude-3",
      "litellm_params": {"model": "anthropic/claude-3-opus", "api_base": "https://api.anthropic.com"},
      "model_info": {"litellm_provider": "anthropic"}
    },
    {
      "model_name": "bedrock-claude",
      "litellm_params": {"model": "bedrock/anthropic.claude-v2"},
      "model_info": {"litellm_provider": "bedrock"}
    }
  ]
}`

// happyPathKeyList matches the default (return_full_object=false) shape
// of LiteLLM's /key/list response: keys[] is a bare list of hashed-token
// strings, wrapped in pagination metadata (total_count, total_pages).
// Real deployments always return the token pre-hashed via
// proxy/utils.py::hash_token().
const happyPathKeyList = `{"keys":["` + fakeHashedTokenA + `","` + fakeHashedTokenB + `"],"total_count":2,"current_page":1,"total_pages":1}`

// happyPathKeyListFullObject is the return_full_object=true expansion —
// keys[] carries objects with the same hashed token plus spend/models.
const happyPathKeyListFullObject = `{"keys":[
  {"token":"` + fakeHashedTokenA + `","spend":12.34,"models":["gpt-4","claude-3"],"key_alias":"eng-team"},
  {"token":"` + fakeHashedTokenB + `","spend":5.67,"models":["claude-3"],"key_alias":"data-team"}
],"total_count":2,"current_page":1,"total_pages":1}`

func TestCollect_HappyPath(t *testing.T) {
	s := newStub(t)
	s.modelInfoBody = happyPathModelInfo
	s.keyListBody = happyPathKeyList
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{
		Credentials: map[string]string{"master_key": fakeMasterKey},
		Timeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if res.IngestData == nil {
		t.Fatal("nil IngestData")
	}

	// Expect: 1 gateway + 1 master + 3 upstream + 2 virtual = 7 nodes,
	// with 6 Credential nodes and 6 EXPOSES_CREDENTIAL edges.
	if got := len(res.IngestData.Graph.Nodes); got != 7 {
		t.Errorf("nodes = %d, want 7 (1 gateway + 6 credentials)", got)
	}
	credCount := 0
	for _, n := range res.IngestData.Graph.Nodes {
		if len(n.Kinds) > 0 && n.Kinds[0] == "Credential" {
			credCount++
		}
	}
	if credCount != 6 {
		t.Errorf("Credential nodes = %d, want 6 (1 master + 3 upstream + 2 virtual)", credCount)
	}

	edgeCount := 0
	for _, e := range res.IngestData.Graph.Edges {
		if e.Kind == "EXPOSES_CREDENTIAL" {
			edgeCount++
		}
	}
	if edgeCount != 6 {
		t.Errorf("EXPOSES_CREDENTIAL edges = %d, want 6", edgeCount)
	}

	if len(res.PartialErrors) != 0 {
		t.Errorf("PartialErrors = %v, want []", res.PartialErrors)
	}
	if res.Summary.CredentialsFound != 6 {
		t.Errorf("Summary.CredentialsFound = %d, want 6", res.Summary.CredentialsFound)
	}

	// The master Credential MUST carry value_hash matching
	// HashCredentialValue(masterKey) — this is the cross-collector
	// merge primitive. Without this the credential-chain demo fails.
	var masterNode *ingest.Node
	for i := range res.IngestData.Graph.Nodes {
		if res.IngestData.Graph.Nodes[i].Properties["type"] == "master_key" {
			masterNode = &res.IngestData.Graph.Nodes[i]
			break
		}
	}
	if masterNode == nil {
		t.Fatal("master Credential node not emitted")
	}
	wantHash := common.HashCredentialValue(fakeMasterKey)
	if got := masterNode.Properties["value_hash"]; got != wantHash {
		t.Errorf("master value_hash = %v, want %v (cross-collector merge primitive)", got, wantHash)
	}

	if masterNode.Properties["value"] != fakeMasterKey {
		t.Errorf("master raw value = %v, want captured credential", masterNode.Properties["value"])
	}
}

func TestCollect_MasterCredentialIdentityIncludesValueHash(t *testing.T) {
	s := newStub(t)
	s.modelInfoBody = `{"data":[]}`
	s.keyListBody = `{"keys":[],"total_count":0,"total_pages":0}`
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	target := action.Target{Kind: "host", Address: strings.TrimPrefix(srv.URL, "http://")}
	collectMaster := func(key string) ingest.Node {
		t.Helper()
		res, err := (&Collector{}).Collect(context.Background(), target, action.CollectOptions{
			Credentials: map[string]string{"master_key": key},
		})
		if err != nil {
			t.Fatalf("collect master key: %v", err)
		}
		for _, node := range res.IngestData.Graph.Nodes {
			if node.Properties["type"] == "master_key" {
				return node
			}
		}
		t.Fatal("master Credential node not emitted")
		return ingest.Node{}
	}

	firstKey := "sk-test-first-litellm-master-key"
	secondKey := "sk-test-second-litellm-master-key"
	first := collectMaster(firstKey)
	repeated := collectMaster(firstKey)
	second := collectMaster(secondKey)

	if first.ID != repeated.ID {
		t.Fatalf("same master key IDs differ: %q != %q", first.ID, repeated.ID)
	}
	if first.ID == second.ID {
		t.Fatalf("different master keys share ID %q", first.ID)
	}
	for _, test := range []struct {
		node ingest.Node
		key  string
	}{
		{node: first, key: firstKey},
		{node: second, key: secondKey},
	} {
		want := ingest.ComputeNodeID(
			"Credential", srv.URL, "litellm-master", common.HashCredentialValue(test.key),
		)
		if test.node.ID != want {
			t.Errorf("master ID = %q, want contextual value-hash ID %q", test.node.ID, want)
		}
	}
}

func TestCollect_GatewayMatchesFingerprintWithoutOwningPosture(t *testing.T) {
	s := newStub(t)
	s.modelInfoBody = `{"data":[]}`
	s.keyListBody = `{"keys":[],"total_count":0,"total_pages":0}`
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	target := action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}
	fingerprinter, err := litellmfp.New()
	if err != nil {
		t.Fatalf("create fingerprinter: %v", err)
	}
	fingerprint, err := fingerprinter.Fingerprint(context.Background(), target)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if !fingerprint.Matched || fingerprint.IngestData == nil ||
		len(fingerprint.IngestData.Graph.Nodes) != 1 {
		t.Fatalf("fingerprint result = %+v, want one matched gateway", fingerprint)
	}

	collection, err := (&Collector{}).Collect(context.Background(), target, action.CollectOptions{
		Credentials: map[string]string{"master_key": fakeMasterKey},
	})
	if err != nil {
		t.Fatalf("collection: %v", err)
	}
	var gateway *ingest.Node
	for i := range collection.IngestData.Graph.Nodes {
		if len(collection.IngestData.Graph.Nodes[i].Kinds) > 0 &&
			collection.IngestData.Graph.Nodes[i].Kinds[0] == "LiteLLMGateway" {
			gateway = &collection.IngestData.Graph.Nodes[i]
			break
		}
	}
	if gateway == nil {
		t.Fatal("collection gateway node missing")
	}

	fingerprintGateway := fingerprint.IngestData.Graph.Nodes[0]
	if gateway.ID != fingerprintGateway.ID {
		t.Fatalf("collection gateway ID = %q, fingerprint ID = %q", gateway.ID, fingerprintGateway.ID)
	}
	if !reflect.DeepEqual(gateway.Kinds, []string{"LiteLLMGateway", "AIService"}) {
		t.Fatalf("collection gateway kinds = %v", gateway.Kinds)
	}
	if len(gateway.Properties) != 0 {
		t.Fatalf("collection gateway properties = %+v, want property-neutral reference", gateway.Properties)
	}
	if gateway.PropertySemantics != ingest.NodePropertySemanticsReferenceOnly {
		t.Fatalf("collection gateway property semantics = %q, want reference_only", gateway.PropertySemantics)
	}
	for _, fingerprintOwned := range []string{
		"auth_method",
		"auth_assurance",
		"auth_evidence",
		"discovered_via",
		"version",
	} {
		if _, exists := gateway.Properties[fingerprintOwned]; exists {
			t.Errorf("collection gateway claimed fingerprint-owned property %q", fingerprintOwned)
		}
	}
}

func TestCollect_PartialFailure_KeyListUnauthorized(t *testing.T) {
	s := newStub(t)
	s.modelInfoBody = happyPathModelInfo
	// /key/list 401 — common in production where the master key is
	// scoped down. The looter must record the error and continue,
	// returning the upstream credentials it did extract.
	s.keyListCode = 401
	s.keyListBody = `{"error": "unauthorized"}`
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{
		Credentials: map[string]string{"master_key": fakeMasterKey},
	})
	if err != nil {
		t.Fatalf("Collect returned err on partial failure: %v", err)
	}
	if len(res.PartialErrors) == 0 {
		t.Fatal("expected non-empty PartialErrors")
	}
	hasKeyListErr := false
	for _, pe := range res.PartialErrors {
		if strings.Contains(pe, "key/list") {
			hasKeyListErr = true
		}
	}
	if !hasKeyListErr {
		t.Errorf("PartialErrors missing key/list entry: %v", res.PartialErrors)
	}
	// Should still have master + 3 upstream credentials.
	credCount := 0
	for _, n := range res.IngestData.Graph.Nodes {
		if len(n.Kinds) > 0 && n.Kinds[0] == "Credential" {
			credCount++
		}
	}
	if credCount != 4 {
		t.Errorf("Credential nodes = %d, want 4 (1 master + 3 upstream)", credCount)
	}
}

func TestCollect_RejectedCandidateIsNotAttributedToGateway(t *testing.T) {
	s := newStub(t)
	s.modelInfoCode = http.StatusUnauthorized
	s.keyListCode = http.StatusUnauthorized
	s.modelInfoBody = `{"error":"unauthorized"}`
	s.keyListBody = `{"error":"unauthorized"}`
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	res, err := (&Collector{}).Collect(context.Background(), action.Target{
		Kind: "url", Address: srv.URL,
	}, action.CollectOptions{Credentials: map[string]string{"master_key": fakeMasterKey}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.PartialFailures != 2 {
		t.Fatalf("partial failures = %d, want 2", res.Summary.PartialFailures)
	}
	for _, node := range res.IngestData.Graph.Nodes {
		if len(node.Kinds) > 0 && node.Kinds[0] == "Credential" {
			t.Fatalf("rejected candidate became credential evidence: %+v", node)
		}
	}
	for _, edge := range res.IngestData.Graph.Edges {
		if edge.Kind == "EXPOSES_CREDENTIAL" {
			t.Fatalf("rejected candidate became exposure evidence: %+v", edge)
		}
	}
}

func TestCollect_LenientModelInfoShape(t *testing.T) {
	// LiteLLM's /model/info shape has drifted across versions; the
	// looter must not fail-fast on unexpected fields. A response with
	// a single entry and no api_base / no api_key still produces an
	// upstream Credential with a synthetic value_hash.
	s := newStub(t)
	s.modelInfoBody = `{"data": [{"model_name": "gpt-4", "litellm_params": {"model": "openai/gpt-4"}, "model_info": {}}]}`
	s.keyListBody = `{"keys": []}`
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{
		Credentials: map[string]string{"master_key": fakeMasterKey},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	credCount := 0
	for _, n := range res.IngestData.Graph.Nodes {
		if len(n.Kinds) > 0 && n.Kinds[0] == "Credential" {
			credCount++
		}
	}
	if credCount != 2 {
		t.Errorf("Credential nodes = %d, want 2 (master + 1 upstream)", credCount)
	}
}

func TestCollect_RequiresMasterKey(t *testing.T) {
	l := &Collector{}
	_, err := l.Collect(context.Background(), action.Target{Address: "127.0.0.1:4000"},
		action.CollectOptions{})
	if err == nil {
		t.Fatal("expected error for missing master_key")
	}
	if !strings.Contains(err.Error(), "master") {
		t.Errorf("err = %v, want one mentioning 'master'", err)
	}
}

func TestCollect_RejectsWhitespaceOnlyMasterKeyBeforeProbing(t *testing.T) {
	s := newStub(t)
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	res, err := (&Collector{}).Collect(context.Background(), action.Target{
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{
		Credentials: map[string]string{"master_key": " \t\n "},
	})
	if err == nil {
		t.Fatal("expected error for whitespace-only master_key")
	}
	if res != nil {
		t.Fatalf("result = %+v, want nil before graph construction", res)
	}
	if len(s.seenMethods) != 0 {
		t.Fatalf("requests = %v, want none for invalid credential input", s.seenMethods)
	}
}

func TestCollect_RetainsCredentialValues(t *testing.T) {
	// When the operator opts in, the master Credential carries the raw
	// value too. The merge-primitive value_hash is unchanged.
	s := newStub(t)
	s.modelInfoBody = `{"data": []}`
	s.keyListBody = happyPathKeyList
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{
		Credentials: map[string]string{"master_key": fakeMasterKey},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var master *ingest.Node
	for i := range res.IngestData.Graph.Nodes {
		if res.IngestData.Graph.Nodes[i].Properties["type"] == "master_key" {
			master = &res.IngestData.Graph.Nodes[i]
		}
	}
	if master == nil {
		t.Fatal("master node missing")
	}
	if got := master.Properties["value"]; got != fakeMasterKey {
		t.Errorf("master.value = %v, want raw observed key", got)
	}
}

// TestCollect_ModelInfoIsIdentityMergeKey verifies that upstream provider
// Credentials from /model/info carry merge_key="identity" — the
// cross-service credential-chain processor must skip these in the
// value_hash join because their value_hash is SHA-256("provider:name"),
// not SHA-256(raw_key). LiteLLM's /model/info strips litellm_params.api_key
// via remove_sensitive_info_from_deployment.
func TestCollect_ModelInfoIsIdentityMergeKey(t *testing.T) {
	s := newStub(t)
	s.modelInfoBody = happyPathModelInfo
	s.keyListBody = `{"keys":[],"total_count":0,"total_pages":0}`
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{
		Credentials: map[string]string{"master_key": fakeMasterKey},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Properties["type"] != "apiKey" {
			continue
		}
		if got, _ := n.Properties["merge_key"].(string); got != "identity" {
			t.Errorf("upstream node %q merge_key = %q, want identity", n.Properties["name"], got)
		}
		if _, hasRaw := n.Properties["value"]; hasRaw {
			t.Errorf("upstream node leaked raw value; /model/info strips upstream api_key server-side")
		}
		if n.Properties["material_status"] != "masked" ||
			n.Properties["exposure_status"] != "not_observed" ||
			n.Properties["high_entropy"] != false {
			t.Errorf("masked provider reference claimed secret exposure: %+v", n.Properties)
		}
		if _, legacy := n.Properties["is_exposed"]; legacy {
			t.Errorf("masked provider reference emitted legacy is_exposed alias: %+v", n.Properties)
		}
	}
}

// TestCollect_KeyList_RequestsFullObject asserts every outgoing /key/list
// request carries return_full_object=true and size=100 — the fix for
// U-CRIT-1 (default List[str] shape) and U-M1 (page cap).
func TestCollect_KeyList_RequestsFullObject(t *testing.T) {
	var (
		mu       sync.Mutex
		gotQuery []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/key/list" {
			mu.Lock()
			gotQuery = append(gotQuery, r.URL.RawQuery)
			mu.Unlock()
			_, _ = w.Write([]byte(happyPathKeyList))
			return
		}
		if r.URL.Path == "/model/info" {
			_, _ = w.Write([]byte(happyPathModelInfo))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	l := &Collector{}
	_, err := l.Collect(context.Background(), action.Target{
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{
		Credentials: map[string]string{"master_key": fakeMasterKey},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(gotQuery) == 0 {
		t.Fatal("no /key/list request observed")
	}
	for i, q := range gotQuery {
		if !strings.Contains(q, "return_full_object=true") {
			t.Errorf("page %d query %q missing return_full_object=true", i+1, q)
		}
		if !strings.Contains(q, "size=100") {
			t.Errorf("page %d query %q missing size=100 (LiteLLM's max)", i+1, q)
		}
		if !strings.Contains(q, fmt.Sprintf("page=%d", i+1)) {
			t.Errorf("page %d query %q missing page=%d", i+1, q, i+1)
		}
	}
}

// TestCollect_KeyList_ValueHashPreserved asserts that the token string
// returned by /key/list — already SHA-256(raw_key).hexdigest() per
// LiteLLM proxy/utils.py::hash_token() — is assigned to value_hash
// directly, without a second hash pass. Double-hashing (U-HIGH-2)
// broke cross-collector merge; the fix is byte-for-byte pass-through.
func TestCollect_KeyList_ValueHashPreserved(t *testing.T) {
	s := newStub(t)
	s.modelInfoBody = `{"data": []}`
	s.keyListBody = happyPathKeyList
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{
		Credentials: map[string]string{"master_key": fakeMasterKey},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	hashes := map[string]bool{}
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Properties["type"] != "virtual_key" {
			continue
		}
		vh, _ := n.Properties["value_hash"].(string)
		hashes[vh] = true
		if got, _ := n.Properties["merge_key"].(string); got != "value_hash" {
			t.Errorf("virtual key %q merge_key = %q, want value_hash", n.Properties["name"], got)
		}
		if n.Properties["material_status"] != "hashed" ||
			n.Properties["exposure_status"] != "not_observed" {
			t.Errorf("hashed virtual-key reference claimed observed material: %+v", n.Properties)
		}
		// Regression: prior double-hash would produce SHA-256(hex) — a
		// different hex string. Assert we pass the fixture through.
		if vh == common.HashCredentialValue(fakeHashedTokenA) ||
			vh == common.HashCredentialValue(fakeHashedTokenB) {
			t.Errorf("virtual key value_hash %q is double-hashed (SHA-256 of the already-hashed token); pass through directly", vh)
		}
	}
	if !hashes[fakeHashedTokenA] || !hashes[fakeHashedTokenB] {
		t.Errorf("expected value_hash values to equal the fixture hashed tokens verbatim; got %+v", hashes)
	}
}

// TestCollect_KeyList_ObjectShape verifies decoding of the
// return_full_object=true response (keys[] is []{token,spend,models,...}).
func TestCollect_KeyList_ObjectShape(t *testing.T) {
	s := newStub(t)
	s.modelInfoBody = `{"data": []}`
	s.keyListBody = happyPathKeyListFullObject
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{
		Credentials: map[string]string{"master_key": fakeMasterKey},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var virtCount int
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Properties["type"] != "virtual_key" {
			continue
		}
		virtCount++
		spend, _ := n.Properties["spend_usd"].(float64)
		if spend == 0 {
			t.Errorf("virtual key %q spend_usd = 0, want spend metadata parsed from object shape", n.Properties["name"])
		}
		models, _ := n.Properties["models"].([]string)
		if len(models) == 0 {
			t.Errorf("virtual key %q models = empty, want models parsed from object shape", n.Properties["name"])
		}
	}
	if virtCount != 2 {
		t.Errorf("virtual key count = %d, want 2 from object-shape fixture", virtCount)
	}
}

// TestCollect_KeyList_PaginatesUntilTotalPages exercises the pagination
// loop: a 3-page fixture returning total_pages=3 must be walked
// entirely, producing 6 virtual keys (2 per page).
func TestCollect_KeyList_PaginatesUntilTotalPages(t *testing.T) {
	var (
		mu       sync.Mutex
		pagesHit []int
	)
	pages := []string{
		`{"keys":["aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa1","aaa2aaa2aaa2aaa2aaa2aaa2aaa2aaa2aaa2aaa2aaa2aaa2aaa2aaa2aaa2aaa2"],"total_count":6,"current_page":1,"total_pages":3}`,
		`{"keys":["bbb1bbb1bbb1bbb1bbb1bbb1bbb1bbb1bbb1bbb1bbb1bbb1bbb1bbb1bbb1bbb1","bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb2"],"total_count":6,"current_page":2,"total_pages":3}`,
		`{"keys":["ccc1ccc1ccc1ccc1ccc1ccc1ccc1ccc1ccc1ccc1ccc1ccc1ccc1ccc1ccc1ccc1","ccc2ccc2ccc2ccc2ccc2ccc2ccc2ccc2ccc2ccc2ccc2ccc2ccc2ccc2ccc2ccc2"],"total_count":6,"current_page":3,"total_pages":3}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/model/info":
			_, _ = w.Write([]byte(`{"data": []}`))
		case "/key/list":
			// Parse the page query param.
			var p int
			_, _ = fmt.Sscanf(r.URL.Query().Get("page"), "%d", &p)
			mu.Lock()
			pagesHit = append(pagesHit, p)
			mu.Unlock()
			if p < 1 || p > len(pages) {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(pages[p-1]))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{
		Credentials: map[string]string{"master_key": fakeMasterKey},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	mu.Lock()
	got := append([]int(nil), pagesHit...)
	mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("pages requested = %v, want [1 2 3]", got)
	}
	for i, p := range got {
		if p != i+1 {
			t.Errorf("page order = %v, want [1 2 3]", got)
			break
		}
	}
	var virtCount int
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Properties["type"] == "virtual_key" {
			virtCount++
		}
	}
	if virtCount != 6 {
		t.Errorf("virtual key count across 3 pages = %d, want 6", virtCount)
	}
}

package ingest

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	collectorcli "github.com/adithyan-ak/agenthound/collector/cli"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	sharedinstruction "github.com/adithyan-ak/agenthound/sdk/instruction"
)

func testCollectionIdentity() ingest.CollectionIdentity {
	identity := ingest.NewCollectionIdentity(
		[]ingest.IdentityEvidence{
			{Kind: "os_instance", Digest: "hmac-sha256:" + strings.Repeat("a", 64)},
			{Kind: "principal", Digest: "hmac-sha256:" + strings.Repeat("b", 64)},
		},
		[]ingest.IdentityEvidence{
			{Kind: "network_profile", Digest: "hmac-sha256:" + strings.Repeat("c", 64)},
		},
		ingest.NetworkClassPrivate,
	)
	identity.Display = ingest.CollectionDisplayLabels{
		Hostname: "target-01", OS: "linux", Architecture: "amd64",
	}
	return identity
}

func validIngestData() *ingest.IngestData {
	scope := ingest.CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	return &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:          ingest.CurrentVersion,
			Type:             ingest.IngestType,
			Identity:         testCollectionIdentity(),
			Collector:        "mcp",
			CollectorVersion: "0.1.0",
			Timestamp:        "2026-04-06T10:30:00Z",
			ScanID:           "scan-001",
			Collection: &ingest.CollectionReport{
				State:        ingest.OutcomeComplete,
				CoverageKeys: []string{scope},
				Outcomes: []ingest.CollectionOutcome{{
					Collector:   "mcp",
					CoverageKey: scope,
					Target:      "https://mcp.example",
					Method:      "enumerate",
					State:       ingest.OutcomeComplete,
					Items:       2,
				}},
			},
			Ruleset:         ingest.EmptyRulesetManifest(),
			IdentitySchemes: ingest.CurrentIdentitySchemes(),
		},
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{
				{
					ID: "sha256:aaa", Kinds: []string{"MCPServer"},
					Properties: map[string]any{
						"name": "srv", "transport": "http", "endpoint": "https://mcp.example",
						"auth_method":    "unknown",
						"auth_assurance": "unknown", "auth_evidence": "unknown",
					},
					ObservationDomains: []string{scope},
				},
				{
					ID: "sha256:bbb", Kinds: []string{"MCPTool"},
					Properties:         map[string]any{"name": "tool"},
					ObservationDomains: []string{scope},
				},
			},
			Edges: []ingest.Edge{
				{
					Source: "sha256:aaa", Target: "sha256:bbb",
					Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool",
					Properties:         map[string]any{"risk_weight": 0.1},
					ObservationDomains: []string{scope},
				},
			},
		},
	}
}

func TestValidatorAcceptsValid(t *testing.T) {
	v := NewValidator()
	if err := v.Validate(validIngestData()); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func validVectorCollectionData() *ingest.IngestData {
	data := validIngestData()
	scope := data.Meta.Collection.CoverageKeys[0]
	qdrantID := "sha256:qdrant"
	collectionID := ingest.ComputeNodeID("VectorCollection", qdrantID, "docs")
	data.Graph.Nodes = []ingest.Node{
		{
			ID: qdrantID, Kinds: []string{"QdrantInstance", "AIService"},
			Properties: map[string]any{
				"objectid": qdrantID, "endpoint": "http://qdrant:6333",
				"auth_method": "unknown", "auth_assurance": "unknown", "auth_evidence": "unknown",
			},
			ObservationDomains: []string{scope},
		},
		{
			ID: collectionID, Kinds: []string{"VectorCollection"},
			Properties:         map[string]any{"objectid": collectionID, "name": "docs"},
			ObservationDomains: []string{scope},
		},
	}
	data.Graph.Edges = []ingest.Edge{{
		Source: qdrantID, Target: collectionID, Kind: "PROVIDES_RESOURCE",
		SourceKind: "QdrantInstance", TargetKind: "VectorCollection",
		Properties: map[string]any{
			"risk_weight": 0.2, "confidence": 1.0,
			"evidence_state": "verified", "last_seen": "2026-08-27T12:00:00Z",
			"evidence": map[string]any{"source": "collections"},
		},
		ObservationDomains: []string{scope},
	}}
	return data
}

func TestValidatorTypedResourceRequiresExactPairAndEvidence(t *testing.T) {
	if err := NewValidator().Validate(validVectorCollectionData()); err != nil {
		t.Fatalf("valid typed resource rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		path string
		edit func(*ingest.IngestData)
	}{
		{
			name: "invalid pair", path: "graph.edges[0]",
			edit: func(data *ingest.IngestData) { data.Graph.Edges[0].SourceKind = "MCPServer" },
		},
		{
			name: "missing evidence state", path: "graph.edges[0].properties.evidence_state",
			edit: func(data *ingest.IngestData) { delete(data.Graph.Edges[0].Properties, "evidence_state") },
		},
		{
			name: "missing timestamp", path: "graph.edges[0].properties.last_seen",
			edit: func(data *ingest.IngestData) { delete(data.Graph.Edges[0].Properties, "last_seen") },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := validVectorCollectionData()
			test.edit(data)
			assertValidationError(t, NewValidator().Validate(data), test.path)
		})
	}
}

func validInstructionEvidenceData(t *testing.T) *ingest.IngestData {
	t.Helper()
	data := validIngestData()
	scope := data.Meta.Collection.CoverageKeys[0]
	evidence, raw, err := sharedinstruction.MarshalBounded(
		sharedinstruction.VerdictSignal,
		[]sharedinstruction.Signal{{
			RuleID: "instruction-ignore-previous", Label: "Ignore Previous Instructions",
			Severity: "critical", Strength: sharedinstruction.StrengthPrimary,
			RawOffset: 7, Line: 2, Column: 1, Match: "Ignore previous instructions",
			ContextBefore: "line 1\n", ContextAfter: "\nline 3",
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	data.Graph.Nodes = []ingest.Node{{
		ID: "sha256:instruction", Kinds: []string{"InstructionFile"},
		Properties: map[string]any{
			"path": "/project/AGENTS.md", "type": "agents.md", "hash": "sha256:" + strings.Repeat("a", 64),
			"instruction_verdict": string(evidence.Verdict), "instruction_scope": "deep",
			"instruction_signal_count": evidence.TotalSignals, "instruction_signal_truncated": evidence.Truncated,
			"instruction_evidence_version": evidence.Version, "instruction_evidence_json": raw,
			"size_bytes": 64, "modified_at": "2026-08-20T12:00:00Z",
		},
		ObservationDomains: []string{scope},
	}}
	data.Graph.Edges = []ingest.Edge{}
	return data
}

func TestValidatorInstructionEvidenceContract(t *testing.T) {
	if err := NewValidator().Validate(validInstructionEvidenceData(t)); err != nil {
		t.Fatalf("valid instruction evidence rejected: %v", err)
	}

	tests := []struct {
		name string
		path string
		edit func(map[string]any)
	}{
		{name: "missing field", path: "graph.nodes[0].properties.instruction_scope", edit: func(p map[string]any) { delete(p, "instruction_scope") }},
		{name: "verdict mismatch", path: "graph.nodes[0].properties.instruction_evidence_json", edit: func(p map[string]any) { p["instruction_verdict"] = "poisoning" }},
		{name: "count mismatch", path: "graph.nodes[0].properties.instruction_signal_count", edit: func(p map[string]any) { p["instruction_signal_count"] = 2 }},
		{name: "version mismatch", path: "graph.nodes[0].properties.instruction_evidence_version", edit: func(p map[string]any) { p["instruction_evidence_version"] = 2 }},
		{name: "offset outside file", path: "graph.nodes[0].properties.instruction_evidence_json.signals[0].match", edit: func(p map[string]any) { p["size_bytes"] = 7 }},
		{name: "non UTC timestamp", path: "graph.nodes[0].properties.modified_at", edit: func(p map[string]any) { p["modified_at"] = "2026-08-20T12:00:00-07:00" }},
		{name: "unknown JSON field", path: "graph.nodes[0].properties.instruction_evidence_json", edit: func(p map[string]any) {
			raw, ok := p["instruction_evidence_json"].(string)
			if !ok {
				panic("instruction evidence fixture is not a string")
			}
			p["instruction_evidence_json"] = strings.TrimSuffix(raw, "}") + `,"unknown":true}`
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := validInstructionEvidenceData(t)
			test.edit(data.Graph.Nodes[0].Properties)
			assertValidationError(t, NewValidator().Validate(data), test.path)
		})
	}
}

func TestValidatorInstructionEvidenceSourceSpan(t *testing.T) {
	tests := []struct {
		name    string
		offset  int
		match   string
		size    int
		wantErr bool
	}{
		{name: "ends exactly at size", offset: 7, match: "abc", size: 10},
		{name: "ends one byte past size", offset: 7, match: "abcd", size: 10, wantErr: true},
		{name: "multibyte uses source bytes", offset: 7, match: "é", size: 9},
		{name: "multibyte one byte short", offset: 7, match: "é", size: 8, wantErr: true},
		{name: "replacement character is conservative", offset: 7, match: "\uFFFD", size: 8},
		{name: "extreme offset cannot overflow", offset: math.MaxInt, match: "abc", size: 64, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := validInstructionEvidenceData(t)
			properties := data.Graph.Nodes[0].Properties
			rawEvidence, ok := properties["instruction_evidence_json"].(string)
			if !ok {
				t.Fatal("instruction_evidence_json is not a string")
			}
			evidence, err := sharedinstruction.ParseEvidenceJSON(rawEvidence)
			if err != nil {
				t.Fatal(err)
			}
			evidence.Signals[0].RawOffset = test.offset
			evidence.Signals[0].Match = test.match
			encoded, err := json.Marshal(evidence)
			if err != nil {
				t.Fatal(err)
			}
			properties["instruction_evidence_json"] = string(encoded)
			properties["size_bytes"] = test.size
			err = NewValidator().Validate(data)
			if test.wantErr {
				assertValidationError(t, err, "graph.nodes[0].properties.instruction_evidence_json.signals[0].match")
			} else if err != nil {
				t.Fatalf("valid source span rejected: %v", err)
			}
		})
	}
}

func TestValidatorAcceptsHistoricalBooleanOnlyInstructionFile(t *testing.T) {
	data := validInstructionEvidenceData(t)
	data.Graph.Nodes[0].Properties = map[string]any{
		"path": "/project/AGENTS.md", "type": "agents.md",
		"hash": "sha256:" + strings.Repeat("a", 64), "is_suspicious": true,
	}
	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("historical V1 instruction node rejected: %v", err)
	}
}

func TestValidatorStrictlyValidatesOptionalScanExecution(t *testing.T) {
	data := validIngestData()
	execution := ingest.NewScanExecution(ingest.ScanModeActive, true, time.Now().UTC())
	if err := ingest.SetScanExecution(&data.Meta, execution); err != nil {
		t.Fatal(err)
	}
	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("valid scan_execution rejected: %v", err)
	}
	value, ok := data.Meta.Extra[ingest.ScanExecutionExtraKey].(map[string]any)
	if !ok {
		t.Fatalf("scan_execution = %T, want map[string]any", data.Meta.Extra[ingest.ScanExecutionExtraKey])
	}
	value["unknown_field"] = true
	assertValidationError(t, NewValidator().Validate(data), "meta.extra.scan_execution")
}

func TestValidatorAcceptsAuthFreeMCPDiscovery(t *testing.T) {
	data := validIngestData()
	for _, property := range []string{"auth_method", "auth_assurance", "auth_evidence"} {
		delete(data.Graph.Nodes[0].Properties, property)
	}
	data.Graph.Nodes[0].Properties["discovered_via"] = "protoscan"
	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("auth-free MCP discovery rejected: %v", err)
	}
}

func TestValidatorAcceptsPostureFreeA2ADiscovery(t *testing.T) {
	data := validIngestData()
	scope := data.Meta.Collection.CoverageKeys[0]
	data.Graph.Nodes = []ingest.Node{{
		ID: "sha256:a2a-discovery", Kinds: []string{"A2AAgent"},
		Properties: map[string]any{
			"endpoint":       "https://agent.example",
			"agent_card_url": "https://agent.example/.well-known/agent-card.json",
			"discovered_via": "protoscan",
			"protocol":       "a2a",
		},
		ObservationDomains: []string{scope},
	}}
	data.Graph.Edges = []ingest.Edge{}
	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("posture-free A2A discovery rejected: %v", err)
	}
}

func TestValidatorRejectsInconsistentCollectionIdentity(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*ingest.CollectionIdentity)
		wantPath string
	}{
		{
			name:     "missing evidence",
			mutate:   func(identity *ingest.CollectionIdentity) { identity.Evidence = nil },
			wantPath: "meta.identity",
		},
		{
			name: "tampered collection point",
			mutate: func(identity *ingest.CollectionIdentity) {
				identity.CollectionPointID = "sha256:" + strings.Repeat("d", 64)
			},
			wantPath: "meta.identity",
		},
		{
			name: "tampered network context",
			mutate: func(identity *ingest.CollectionIdentity) {
				identity.NetworkContextID = "sha256:" + strings.Repeat("e", 64)
			},
			wantPath: "meta.identity",
		},
		{
			name:     "tampered quality",
			mutate:   func(identity *ingest.CollectionIdentity) { identity.Quality = ingest.IdentityQualityWeak },
			wantPath: "meta.identity",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := validIngestData()
			test.mutate(&data.Meta.Identity)
			assertValidationError(t, NewValidator().Validate(data), test.wantPath)
		})
	}
}

func TestValidatorAcceptsCollectorProducedRootCoverage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	configPath := filepath.Join(dir, ".vscode", "mcp.json")
	outputPath := filepath.Join(dir, "scan.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	if err := os.WriteFile(
		configPath,
		[]byte(`{"servers":{}}`),
		0o600,
	); err != nil {
		t.Fatalf("write config: %v", err)
	}

	originalArgs := os.Args
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	os.Args = []string{
		"agenthound",
		"scan",
		"--stealth",
		"--timeout", "30s",
		"--output", outputPath,
		"--quiet",
	}
	defer func() {
		os.Args = originalArgs
		_ = os.Chdir(originalDir)
	}()

	if err := collectorcli.Execute(); err != nil {
		t.Fatalf("produce scan: %v", err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read scan: %v", err)
	}
	var data ingest.IngestData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("decode scan: %v", err)
	}
	if err := NewValidator().Validate(&data); err != nil {
		if validation, ok := err.(*ValidationError); ok {
			t.Logf("validation errors: %+v", validation.Errors)
		}
		t.Fatalf("collector-produced scan rejected: %v", err)
	}

	states := ingest.CoverageStates(data.Meta.Collection)
	if _, exists := states[ingest.CollectorRootCoverageKey("scan")]; !exists {
		t.Fatalf("collector coverage states = %v, want autonomous scan root", states)
	}
	if len(data.Meta.Collection.AuthoritativeRoots) != 2 {
		t.Fatalf("instruction roots = %+v, want exact user and project", data.Meta.Collection.AuthoritativeRoots)
	}
	currentContract := ingest.CurrentInstructionRegistryContract()
	for _, root := range data.Meta.Collection.AuthoritativeRoots {
		if root.RegistryContract == nil || !root.RegistryContract.Equal(currentContract) {
			t.Fatalf("instruction root contract = %+v, want %+v", root.RegistryContract, currentContract)
		}
	}
}

func TestValidatorAcceptsCanonicalLocalProcessAuthTuple(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].Properties["auth_evidence"] = "local_process"
	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("canonical unknown/unknown/local_process tuple rejected: %v", err)
	}
}

func TestValidatorRejectsLocalProcessAnonymousTuple(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].Properties["auth_method"] = "none"
	data.Graph.Nodes[0].Properties["auth_assurance"] = "unauthenticated"
	data.Graph.Nodes[0].Properties["auth_evidence"] = "local_process"
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[0].properties.auth_evidence",
	)
}

func TestValidatorConfiguredAuthTupleMatrix(t *testing.T) {
	for _, test := range []struct {
		name      string
		method    string
		assurance string
		evidence  string
	}{
		{name: "unknown no observation", method: "unknown", assurance: "unknown", evidence: "unknown"},
		{name: "unknown ambiguous declaration", method: "unknown", assurance: "unknown", evidence: "declared_security_scheme"},
		{name: "unknown MCP query credential", method: "unknown", assurance: "unknown", evidence: "configured_credential"},
		{name: "unknown local process", method: "unknown", assurance: "unknown", evidence: "local_process"},
		{name: "unconfirmed none", method: "none", assurance: "unauthenticated", evidence: "unknown"},
		{name: "A2A empty security requirement", method: "none", assurance: "unauthenticated", evidence: "declared_security_scheme"},
		{name: "confirmed anonymous", method: "none", assurance: "unauthenticated", evidence: "anonymous_probe_succeeded"},
		{name: "basic configured", method: "basic", assurance: "weak", evidence: "configured_credential"},
		{name: "basic declared", method: "basic", assurance: "weak", evidence: "declared_security_scheme"},
		{name: "api key configured", method: "apiKey", assurance: "weak", evidence: "configured_credential"},
		{name: "api key declared", method: "apiKey", assurance: "weak", evidence: "declared_security_scheme"},
		{name: "bearer configured", method: "bearer", assurance: "moderate", evidence: "configured_credential"},
		{name: "bearer declared", method: "bearer", assurance: "moderate", evidence: "declared_security_scheme"},
		{name: "oauth configured", method: "oauth", assurance: "strong", evidence: "configured_credential"},
		{name: "oauth declared", method: "oauth", assurance: "strong", evidence: "declared_security_scheme"},
		{name: "oidc configured", method: "oidc", assurance: "strong", evidence: "configured_credential"},
		{name: "oidc declared", method: "oidc", assurance: "strong", evidence: "declared_security_scheme"},
		{name: "mtls configured", method: "mtls", assurance: "strong", evidence: "configured_credential"},
		{name: "mtls declared", method: "mtls", assurance: "strong", evidence: "declared_security_scheme"},
		{name: "custom configured", method: "custom", assurance: "unknown", evidence: "configured_credential"},
		{name: "custom declared", method: "custom", assurance: "unknown", evidence: "declared_security_scheme"},
	} {
		t.Run(test.name, func(t *testing.T) {
			errs := validateAuthProperties(map[string]any{
				"auth_method": test.method, "auth_assurance": test.assurance,
				"auth_evidence": test.evidence,
			}, 0)
			if len(errs) != 0 {
				t.Fatalf("producer-compatible configured tuple rejected: %+v", errs)
			}
		})
	}
}

func TestValidatorRejectsConfiguredAuthEvidenceMismatch(t *testing.T) {
	for _, test := range []struct {
		name      string
		method    string
		assurance string
		evidence  string
	}{
		{name: "bearer cannot claim anonymous probe", method: "bearer", assurance: "moderate", evidence: "anonymous_probe_succeeded"},
		{name: "none cannot claim configured credential", method: "none", assurance: "unauthenticated", evidence: "configured_credential"},
		{name: "unknown cannot claim anonymous probe", method: "unknown", assurance: "unknown", evidence: "anonymous_probe_succeeded"},
		{name: "basic cannot use unknown evidence", method: "basic", assurance: "weak", evidence: "unknown"},
		{name: "custom cannot use unknown evidence", method: "custom", assurance: "unknown", evidence: "unknown"},
		{name: "oauth cannot claim local process", method: "oauth", assurance: "strong", evidence: "local_process"},
		{name: "none cannot claim local process", method: "none", assurance: "unauthenticated", evidence: "local_process"},
	} {
		t.Run(test.name, func(t *testing.T) {
			errs := validateAuthProperties(map[string]any{
				"auth_method": test.method, "auth_assurance": test.assurance,
				"auth_evidence": test.evidence,
			}, 0)
			if len(errs) == 0 {
				t.Fatal("contradictory configured auth evidence was accepted")
			}
			if errs[len(errs)-1].Path != "graph.nodes[0].properties.auth_evidence" {
				t.Fatalf("error path = %q, want auth_evidence", errs[len(errs)-1].Path)
			}
		})
	}
}

func TestValidatorRejectsConfiguredAuthMethodAssuranceMismatch(t *testing.T) {
	for _, test := range []struct {
		method, assurance string
	}{
		{method: "none", assurance: "unknown"},
		{method: "unknown", assurance: "unauthenticated"},
		{method: "basic", assurance: "moderate"},
		{method: "apiKey", assurance: "strong"},
		{method: "bearer", assurance: "weak"},
		{method: "oauth", assurance: "moderate"},
		{method: "oidc", assurance: "weak"},
		{method: "mtls", assurance: "moderate"},
		{method: "custom", assurance: "strong"},
	} {
		t.Run(test.method+"_"+test.assurance, func(t *testing.T) {
			errs := validateAuthProperties(map[string]any{
				"auth_method": test.method, "auth_assurance": test.assurance,
				"auth_evidence": "configured_credential",
			}, 0)
			if len(errs) == 0 {
				t.Fatal("configured method/assurance mismatch was accepted")
			}
		})
	}
}

func TestValidatorRejectsPartialConfiguredAuthTuple(t *testing.T) {
	for _, missing := range []string{"auth_method", "auth_assurance", "auth_evidence"} {
		t.Run(missing, func(t *testing.T) {
			properties := map[string]any{
				"auth_method": "bearer", "auth_assurance": "moderate",
				"auth_evidence": "configured_credential",
			}
			delete(properties, missing)
			errs := validateAuthProperties(properties, 0)
			if len(errs) == 0 {
				t.Fatal("partial configured auth tuple was accepted")
			}
			wantPath := "graph.nodes[0].properties." + missing
			for _, fieldErr := range errs {
				if fieldErr.Path == wantPath {
					return
				}
			}
			t.Fatalf("errors = %+v, want path %q", errs, wantPath)
		})
	}
}

func TestValidatorAcceptsObservedMCPAuthTupleMatrix(t *testing.T) {
	tests := []struct {
		name      string
		transport string
		status    string
		method    string
		assurance string
		evidence  string
	}{
		{
			name: "reachable anonymous HTTP", transport: "http", status: "reachable",
			method: "none", assurance: "unauthenticated", evidence: "anonymous_probe_succeeded",
		},
		{
			name: "reachable bearer HTTP", transport: "http", status: "reachable",
			method: "bearer", assurance: "moderate", evidence: "configured_credential",
		},
		{
			name: "reachable query credential with unknown scheme", transport: "http", status: "reachable",
			method: "unknown", assurance: "unknown", evidence: "configured_credential",
		},
		{
			name: "unreachable network server", transport: "http", status: "unreachable",
			method: "unknown", assurance: "unknown", evidence: "unknown",
		},
		{
			name: "reachable local process", transport: "stdio", status: "reachable",
			method: "unknown", assurance: "unknown", evidence: "local_process",
		},
		{
			name: "reachable custom authorization", transport: "http", status: "reachable",
			method: "custom", assurance: "unknown", evidence: "configured_credential",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			properties := map[string]any{
				"transport":               test.transport,
				"status":                  test.status,
				"observed_auth_method":    test.method,
				"observed_auth_assurance": test.assurance,
				"observed_auth_evidence":  test.evidence,
			}
			if errs := validateObservedMCPAuthProperties(properties, 0); len(errs) != 0 {
				t.Fatalf("valid observed tuple rejected: %+v", errs)
			}
		})
	}
}

func TestValidatorRejectsPartialOrContradictoryObservedMCPAuthTuple(t *testing.T) {
	tests := []struct {
		name       string
		properties map[string]any
	}{
		{
			name: "partial tuple",
			properties: map[string]any{
				"transport": "http", "status": "reachable",
				"observed_auth_method": "none",
			},
		},
		{
			name: "method assurance mismatch",
			properties: map[string]any{
				"transport": "http", "status": "reachable",
				"observed_auth_method": "bearer", "observed_auth_assurance": "strong",
				"observed_auth_evidence": "configured_credential",
			},
		},
		{
			name: "forged anonymous result on unreachable server",
			properties: map[string]any{
				"transport": "http", "status": "unreachable",
				"observed_auth_method": "none", "observed_auth_assurance": "unauthenticated",
				"observed_auth_evidence": "anonymous_probe_succeeded",
			},
		},
		{
			name: "none from configured credential",
			properties: map[string]any{
				"transport": "http", "status": "reachable",
				"observed_auth_method": "none", "observed_auth_assurance": "unauthenticated",
				"observed_auth_evidence": "configured_credential",
			},
		},
		{
			name: "local process claim on HTTP",
			properties: map[string]any{
				"transport": "http", "status": "reachable",
				"observed_auth_method": "unknown", "observed_auth_assurance": "unknown",
				"observed_auth_evidence": "local_process",
			},
		},
		{
			name: "credential observation claim on stdio",
			properties: map[string]any{
				"transport": "stdio", "status": "reachable",
				"observed_auth_method": "bearer", "observed_auth_assurance": "moderate",
				"observed_auth_evidence": "configured_credential",
			},
		},
		{
			name: "unsupported evidence",
			properties: map[string]any{
				"transport": "http", "status": "reachable",
				"observed_auth_method": "none", "observed_auth_assurance": "unauthenticated",
				"observed_auth_evidence": "caller_said_so",
			},
		},
		{
			name: "configured-only declaration presented as observation",
			properties: map[string]any{
				"transport": "http", "status": "reachable",
				"observed_auth_method": "bearer", "observed_auth_assurance": "moderate",
				"observed_auth_evidence": "declared_security_scheme",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if errs := validateObservedMCPAuthProperties(test.properties, 0); len(errs) == 0 {
				t.Fatal("contradictory observed tuple was accepted")
			}
		})
	}
}

func TestValidatorEnforcesObservedMCPAuthTupleAtIngestBoundary(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].Properties["status"] = "reachable"
	data.Graph.Nodes[0].Properties["observed_auth_method"] = "none"
	data.Graph.Nodes[0].Properties["observed_auth_assurance"] = "unauthenticated"
	data.Graph.Nodes[0].Properties["observed_auth_evidence"] = "anonymous_probe_succeeded"
	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("valid observed anonymous tuple rejected: %v", err)
	}

	for _, property := range []string{"auth_method", "auth_assurance", "auth_evidence"} {
		delete(data.Graph.Nodes[0].Properties, property)
	}
	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("observed-only MCP tuple rejected: %v", err)
	}

	delete(data.Graph.Nodes[0].Properties, "observed_auth_assurance")
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[0].properties.observed_auth_assurance",
	)
}

func TestValidatorAcceptsConfirmedObservedA2AAuthTuple(t *testing.T) {
	properties := map[string]any{
		"observed_auth_method":    "none",
		"observed_auth_assurance": "unauthenticated",
		"observed_auth_evidence":  "anonymous_probe_succeeded",
		"auth_probe_method":       "get_task_nonexistent",
		"auth_probe_status":       "anonymous_protocol_access",
		"auth_probe_detail":       "task_not_found_v1",
	}
	if errs := validateObservedA2AAuthProperties(properties, 0); len(errs) != 0 {
		t.Fatalf("confirmed read-only A2A observation rejected: %+v", errs)
	}

	// Non-positive probes may preserve diagnostics, but no observed auth tuple.
	if errs := validateObservedA2AAuthProperties(map[string]any{
		"auth_probe_method": "get_task_nonexistent",
		"auth_probe_status": "authentication_required",
		"auth_probe_detail": "http_unauthorized",
	}, 0); len(errs) != 0 {
		t.Fatalf("metadata-only protected A2A probe rejected: %+v", errs)
	}
}

func TestValidatorAcceptsCanonicalA2AProbeDetailVocabulary(t *testing.T) {
	detailsByStatus := map[string][]string{
		"anonymous_protocol_access": {"task_not_found_v1", "task_not_found_v0_3"},
		"authentication_required":   {"http_unauthorized", "http_forbidden"},
		"unknown": {
			"no_preferred_interface", "nonconformant_preferred_interface",
			"unsupported_protocol_binding", "unsupported_protocol_version",
			"invalid_preferred_interface_url", "query_interface_not_probeable",
			"cross_origin_interface",
			"random_id_generation_failed", "request_encoding_failed",
			"request_creation_failed", "transport_unavailable", "timeout",
			"context_canceled", "transport_error", "redirect_response",
			"unexpected_http_status", "non_json_response", "response_too_large",
			"malformed_jsonrpc_response", "unexpected_jsonrpc_response",
			"response_id_mismatch", "non_task_not_found_error",
		},
	}
	for status, details := range detailsByStatus {
		for _, detail := range details {
			t.Run(status+"_"+detail, func(t *testing.T) {
				properties := map[string]any{
					"auth_probe_method": "get_task_nonexistent",
					"auth_probe_status": status,
					"auth_probe_detail": detail,
				}
				if status == "anonymous_protocol_access" {
					properties["observed_auth_method"] = "none"
					properties["observed_auth_assurance"] = "unauthenticated"
					properties["observed_auth_evidence"] = "anonymous_probe_succeeded"
				}
				if errs := validateObservedA2AAuthProperties(properties, 0); len(errs) != 0 {
					t.Fatalf("canonical A2A probe diagnostic rejected: %+v", errs)
				}
			})
		}
	}
}

func TestValidatorRejectsUnprovenObservedA2AAuth(t *testing.T) {
	valid := func() map[string]any {
		return map[string]any{
			"observed_auth_method":    "none",
			"observed_auth_assurance": "unauthenticated",
			"observed_auth_evidence":  "anonymous_probe_succeeded",
			"auth_probe_method":       "get_task_nonexistent",
			"auth_probe_status":       "anonymous_protocol_access",
			"auth_probe_detail":       "task_not_found_v0_3",
		}
	}
	for _, test := range []struct {
		name     string
		wantPath string
		mutate   func(map[string]any)
	}{
		{name: "partial observed tuple", wantPath: "observed_auth_assurance", mutate: func(p map[string]any) { delete(p, "observed_auth_assurance") }},
		{name: "missing probe method", wantPath: "auth_probe_method", mutate: func(p map[string]any) { delete(p, "auth_probe_method") }},
		{name: "missing probe status", wantPath: "auth_probe_status", mutate: func(p map[string]any) { delete(p, "auth_probe_status") }},
		{name: "missing probe detail", wantPath: "auth_probe_detail", mutate: func(p map[string]any) { delete(p, "auth_probe_detail") }},
		{name: "orphan positive status", wantPath: "observed_auth_method", mutate: func(p map[string]any) {
			delete(p, "observed_auth_method")
			delete(p, "observed_auth_assurance")
			delete(p, "observed_auth_evidence")
		}},
		{name: "arbitrary status", wantPath: "auth_probe_status", mutate: func(p map[string]any) { p["auth_probe_status"] = "looks_open" }},
		{name: "wrong status type", wantPath: "auth_probe_status", mutate: func(p map[string]any) { p["auth_probe_status"] = 200 }},
		{name: "wrong method type", wantPath: "auth_probe_method", mutate: func(p map[string]any) { p["auth_probe_method"] = true }},
		{name: "wrong detail type", wantPath: "auth_probe_detail", mutate: func(p map[string]any) { p["auth_probe_detail"] = []string{"task_not_found_v1"} }},
		{name: "wrong observed type", wantPath: "observed_auth_method", mutate: func(p map[string]any) { p["observed_auth_method"] = false }},
		{name: "unbounded detail", wantPath: "auth_probe_detail", mutate: func(p map[string]any) { p["auth_probe_detail"] = "raw server response" }},
		{name: "protected response cannot prove anonymous", wantPath: "observed_auth_method", mutate: func(p map[string]any) {
			p["auth_probe_status"] = "authentication_required"
			p["auth_probe_detail"] = "http_unauthorized"
		}},
		{name: "unknown response cannot prove anonymous", wantPath: "observed_auth_method", mutate: func(p map[string]any) {
			p["auth_probe_status"] = "unknown"
			p["auth_probe_detail"] = "timeout"
		}},
		{name: "card fetch is not an auth probe", wantPath: "auth_probe_method", mutate: func(p map[string]any) { p["auth_probe_method"] = "agent_card_get" }},
		{name: "declared scheme is not observed access", wantPath: "observed_auth_evidence", mutate: func(p map[string]any) { p["observed_auth_evidence"] = "declared_security_scheme" }},
		{name: "generic authenticated tuple is not supported", wantPath: "observed_auth_method", mutate: func(p map[string]any) {
			p["observed_auth_method"] = "bearer"
			p["observed_auth_assurance"] = "moderate"
			p["observed_auth_evidence"] = "configured_credential"
		}},
		{name: "non-positive unknown tuple must be omitted", wantPath: "observed_auth_method", mutate: func(p map[string]any) {
			p["observed_auth_method"] = "unknown"
			p["observed_auth_assurance"] = "unknown"
			p["observed_auth_evidence"] = "unknown"
			p["auth_probe_status"] = "unknown"
			p["auth_probe_detail"] = "timeout"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			properties := valid()
			test.mutate(properties)
			errs := validateObservedA2AAuthProperties(properties, 0)
			if len(errs) == 0 {
				t.Fatal("unproven A2A observed authentication was accepted")
			}
			wantPath := "graph.nodes[0].properties." + test.wantPath
			for _, fieldErr := range errs {
				if fieldErr.Path == wantPath {
					return
				}
			}
			t.Fatalf("errors = %+v, want path %q", errs, wantPath)
		})
	}
}

func TestValidatorEnforcesObservedA2AAuthAtIngestBoundary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "valid_a2a_scan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var data ingest.IngestData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	data.Meta.Version = ingest.CurrentVersion
	data.Meta.Identity = testCollectionIdentity()
	properties := data.Graph.Nodes[0].Properties
	properties["observed_auth_method"] = "none"
	properties["observed_auth_assurance"] = "unauthenticated"
	properties["observed_auth_evidence"] = "anonymous_probe_succeeded"
	properties["auth_probe_method"] = "get_task_nonexistent"
	properties["auth_probe_status"] = "anonymous_protocol_access"
	properties["auth_probe_detail"] = "task_not_found_v1"
	if err := NewValidator().Validate(&data); err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			t.Fatalf("valid A2A runtime observation rejected: %+v", validationErr.Errors)
		}
		t.Fatalf("valid A2A runtime observation rejected: %v", err)
	}

	delete(properties, "auth_probe_status")
	assertValidationError(
		t,
		NewValidator().Validate(&data),
		"graph.nodes[0].properties.auth_probe_status",
	)
}

func TestValidatorAcceptsDeclaredObservationDomains(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	if err := v.Validate(data); err != nil {
		t.Fatalf("declared observation domain rejected: %v", err)
	}
}

func TestValidatorAcceptsPropertyNeutralNodeReference(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].Properties = map[string]any{}
	data.Graph.Nodes[0].PropertySemantics = ingest.NodePropertySemanticsReferenceOnly

	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("property-neutral node reference rejected: %v", err)
	}
}

func TestValidatorRejectsPropertiesOnNodeReference(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].PropertySemantics = ingest.NodePropertySemanticsReferenceOnly

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[0].properties",
	)
}

func TestValidatorRejectsUnknownNodePropertySemantics(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].PropertySemantics = "compatibility"

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[0].property_semantics",
	)
}

func TestValidatorAcceptsAuthoritativeRootActiveSet(t *testing.T) {
	data := validIngestData()
	child := data.Meta.Collection.CoverageKeys[0]
	root := ingest.CanonicalCoverageKey("mcp", "root", "collect")
	data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, root)
	data.Meta.Collection.AuthoritativeRoots = []ingest.CoverageRoot{{
		CoverageKey:       root,
		ChildCoverageKeys: []string{child},
	}}
	data.Meta.Collection.Outcomes = append(
		data.Meta.Collection.Outcomes,
		ingest.CollectionOutcome{
			Collector:   "mcp",
			CoverageKey: root,
			Target:      "mcp",
			Method:      "collect",
			State:       ingest.OutcomeComplete,
		},
	)
	ingest.EnsureCoverageParentage(data.Meta.Collection)

	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("authoritative root active set rejected: %v", err)
	}
}

func TestValidatorCollectorRootExcludesIndependentInstructionOwnership(t *testing.T) {
	data, _, _ := validInstructionRootData(ingest.OutcomeComplete)
	collectorRoot := ingest.CollectorRootCoverageKey("config")
	data.Meta.Collection.CoverageKeys = append(
		data.Meta.Collection.CoverageKeys,
		collectorRoot,
	)
	data.Meta.Collection.AuthoritativeRoots = append(
		data.Meta.Collection.AuthoritativeRoots,
		ingest.CoverageRoot{
			CoverageKey:       collectorRoot,
			ChildCoverageKeys: []string{},
		},
	)
	data.Meta.Collection.Outcomes = append(
		data.Meta.Collection.Outcomes,
		ingest.CollectionOutcome{
			Collector: "config", CoverageKey: collectorRoot,
			Target: "config", Method: "collect", State: ingest.OutcomeComplete,
		},
	)
	data.Meta.Collection.State = ingest.AggregateOutcomeState(data.Meta.Collection.Outcomes)

	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("independent instruction ownership rejected: %v", err)
	}
}

func TestValidatorRejectsAuthoritativeRootMissingDeclaredChild(t *testing.T) {
	data := validIngestData()
	root := ingest.CanonicalCoverageKey("mcp", "root", "collect")
	data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, root)
	data.Meta.Collection.AuthoritativeRoots = []ingest.CoverageRoot{{
		CoverageKey: root,
	}}
	data.Meta.Collection.Outcomes = append(
		data.Meta.Collection.Outcomes,
		ingest.CollectionOutcome{
			Collector:   "mcp",
			CoverageKey: root,
			Target:      "mcp",
			Method:      "collect",
			State:       ingest.OutcomeComplete,
		},
	)

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"meta.collection.authoritative_roots[0].child_coverage_keys",
	)
}

func TestValidatorAcceptsAllDependencyEdge(t *testing.T) {
	data := validIngestData()
	secondScope := ingest.CanonicalCoverageKey("mcp", "target", "https://second.example")
	data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, secondScope)
	data.Meta.Collection.Outcomes = append(data.Meta.Collection.Outcomes, ingest.CollectionOutcome{
		Collector:   "mcp",
		CoverageKey: secondScope,
		Target:      "https://second.example",
		Method:      "enumerate",
		State:       ingest.OutcomeComplete,
	})
	data.Graph.Edges[0].ObservationDomains = append(
		data.Graph.Edges[0].ObservationDomains,
		secondScope,
	)
	data.Graph.Edges[0].ObservationSemantics = ingest.ObservationSemanticsAllDependencies

	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("all-dependency edge rejected: %v", err)
	}
}

func TestValidatorRejectsAllDependenciesWithOneDomain(t *testing.T) {
	data := validIngestData()
	data.Graph.Edges[0].ObservationSemantics = ingest.ObservationSemanticsAllDependencies
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.edges[0].observation_semantics",
	)
}

func TestValidatorRejectsUndeclaredObservationDomain(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes[0].ObservationDomains = []string{
		ingest.CanonicalCoverageKey("config", "path", "/tmp/config.json"),
	}

	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[0].observation_domains[0]")
}

func TestValidatorRejectsBadVersion(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.Version = 99
	err := v.Validate(data)
	var versionErr *UnsupportedVersionError
	if !errors.As(err, &versionErr) {
		t.Fatalf("error = %T %v, want UnsupportedVersionError", err, err)
	}
	if versionErr.Received != 99 || versionErr.Supported != ingest.CurrentVersion {
		t.Fatalf("version error = %+v", versionErr)
	}
	if !strings.Contains(versionErr.Error(), "requires version 1") {
		t.Fatalf("version error is not actionable: %v", versionErr)
	}
	if !strings.Contains(versionErr.Action, "upgrade agenthound-server") {
		t.Fatalf("version action is not actionable: %q", versionErr.Action)
	}
}

func TestValidatorRejectsMissingVersion(t *testing.T) {
	data := validIngestData()
	data.Meta.Version = 0
	var versionErr *UnsupportedVersionError
	if !errors.As(NewValidator().Validate(data), &versionErr) {
		t.Fatal("missing version did not return UnsupportedVersionError")
	}
}

func TestValidatorInstructionRegistryContractPreflight(t *testing.T) {
	data, root, _ := validInstructionRootData(ingest.OutcomeComplete)
	if err := Preflight(data); err != nil {
		t.Fatalf("current registry contract rejected: %v", err)
	}

	data.Meta.Collection.AuthoritativeRoots[0].RegistryContract = nil
	err := Preflight(data)
	var contractErr *RegistryContractMismatchError
	if !errors.As(err, &contractErr) {
		t.Fatalf("missing contract error = %T %v, want RegistryContractMismatchError", err, err)
	}
	if contractErr.RootCoverageKey != root || contractErr.Received != nil {
		t.Fatalf("contract error = %+v", contractErr)
	}
	if !contractErr.Supported.Equal(ingest.CurrentInstructionRegistryContract()) {
		t.Fatalf("supported contract = %+v", contractErr.Supported)
	}

	foreign := ingest.CurrentInstructionRegistryContract()
	foreign.Digest = "sha256:" + strings.Repeat("f", 64)
	data.Meta.Collection.AuthoritativeRoots[0].RegistryContract = &foreign
	err = Preflight(data)
	if !errors.As(err, &contractErr) || contractErr.Received == nil ||
		contractErr.Received.Digest != foreign.Digest {
		t.Fatalf("foreign contract error = %T %+v", err, contractErr)
	}

	for name, generation := range map[string]int{
		"zero":   0,
		"future": ingest.InstructionRegistryGeneration + 1,
	} {
		t.Run(name, func(t *testing.T) {
			candidate, _, _ := validInstructionRootData(ingest.OutcomeComplete)
			received := ingest.CurrentInstructionRegistryContract()
			received.Generation = generation
			candidate.Meta.Collection.AuthoritativeRoots[0].RegistryContract = &received
			var mismatch *RegistryContractMismatchError
			if err := Preflight(candidate); !errors.As(err, &mismatch) {
				t.Fatalf("generation %d error = %T %v", generation, err, err)
			}
		})
	}
}

func TestValidatorRejectsContractOnNonInstructionRoot(t *testing.T) {
	data := validIngestData()
	child := data.Meta.Collection.CoverageKeys[0]
	root := ingest.CanonicalCoverageKey("mcp", "root", "collect")
	contract := ingest.CurrentInstructionRegistryContract()
	data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, root)
	data.Meta.Collection.AuthoritativeRoots = []ingest.CoverageRoot{{
		CoverageKey: root, ChildCoverageKeys: []string{child}, RegistryContract: &contract,
	}}
	data.Meta.Collection.Outcomes[0].ParentCoverageKey = root
	data.Meta.Collection.Outcomes = append(data.Meta.Collection.Outcomes, ingest.CollectionOutcome{
		Collector: "mcp", CoverageKey: root, Target: "mcp",
		Method: "collect", State: ingest.OutcomeComplete,
	})

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"meta.collection.authoritative_roots[0].registry_contract",
	)
}

func TestValidatorAllowsCompleteChildFactsUnderIncompleteInstructionRoot(t *testing.T) {
	for _, mode := range []struct {
		name   string
		method string
	}{
		{"exact_user", ingest.InstructionMethodExactUser},
		{"exact_project", ingest.InstructionMethodExactProject},
		{"deep", ingest.InstructionMethodDeep},
	} {
		for _, state := range []ingest.OutcomeState{
			ingest.OutcomeTruncated,
			ingest.OutcomePartial,
			ingest.OutcomeFailed,
		} {
			t.Run(mode.name+"/"+string(state), func(t *testing.T) {
				data, _, _ := validInstructionRootDataFor(mode.method, state)
				if err := NewValidator().Validate(data); err != nil {
					t.Fatalf("complete child under limited root rejected: %v", err)
				}
			})
		}
	}
}

func TestValidatorAcceptsIncompleteInstructionChildAndRootOwnedFacts(t *testing.T) {
	data, _, child := validInstructionRootDataFor(
		ingest.InstructionMethodExactUser,
		ingest.OutcomePartial,
	)
	for i := range data.Meta.Collection.Outcomes {
		if data.Meta.Collection.Outcomes[i].CoverageKey == child {
			data.Meta.Collection.Outcomes[i].State = ingest.OutcomePartial
			data.Meta.Collection.Outcomes[i].Error = "file read incomplete"
		}
	}
	data.Meta.Collection.State = ingest.AggregateOutcomeState(data.Meta.Collection.Outcomes)
	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("partial instruction child facts rejected: %v", err)
	}

	data, root, _ := validInstructionRootDataFor(
		ingest.InstructionMethodExactUser,
		ingest.OutcomeFailed,
	)
	for i := range data.Graph.Nodes {
		data.Graph.Nodes[i].ObservationDomains = []string{root}
	}
	for i := range data.Graph.Edges {
		data.Graph.Edges[i].ObservationDomains = []string{root}
	}
	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("failed instruction root facts rejected: %v", err)
	}
}

func TestValidatorAcceptsFactsOwnedByIncompleteDomain(t *testing.T) {
	data := validIngestData()
	child := data.Meta.Collection.Outcomes[0].CoverageKey
	data.Meta.Collection.Outcomes[0].State = ingest.OutcomePartial
	data.Meta.Collection.Outcomes[0].Error = "read incomplete"
	data.Meta.Collection.State = ingest.AggregateOutcomeState(data.Meta.Collection.Outcomes)
	for i := range data.Graph.Nodes {
		data.Graph.Nodes[i].ObservationDomains = []string{child}
	}
	for i := range data.Graph.Edges {
		data.Graph.Edges[i].ObservationDomains = []string{child}
	}

	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("partial-domain facts rejected: %v", err)
	}
}

func TestValidatorRejectsOrphanInstructionSource(t *testing.T) {
	data, _, child := validInstructionRootData(ingest.OutcomeComplete)
	data.Meta.Collection.AuthoritativeRoots[0].ChildCoverageKeys = nil
	data.Meta.Collection.Outcomes[1].ParentCoverageKey = ""

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"meta.collection.outcomes[1].parent_coverage_key",
	)
	if data.Meta.Collection.Outcomes[1].CoverageKey != child {
		t.Fatal("test did not mutate the intended instruction source")
	}
}

func TestValidatorRejectsInstructionSourceWithWrongParent(t *testing.T) {
	data, _, child := validInstructionRootDataFor(
		ingest.InstructionMethodExactUser,
		ingest.OutcomePartial,
	)
	wrongParent := ""
	for _, outcome := range data.Meta.Collection.Outcomes {
		if outcome.Method == ingest.InstructionMethodExactProject {
			wrongParent = outcome.CoverageKey
			break
		}
	}
	for i := range data.Meta.Collection.Outcomes {
		if data.Meta.Collection.Outcomes[i].CoverageKey == child {
			data.Meta.Collection.Outcomes[i].ParentCoverageKey = wrongParent
		}
	}
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"meta.collection.outcomes[1].parent_coverage_key",
	)
}

func TestValidatorRejectsDescendantBelowInstructionSource(t *testing.T) {
	data, _, child := validInstructionRootDataFor(
		ingest.InstructionMethodDeep,
		ingest.OutcomePartial,
	)
	grandchild := ingest.CanonicalCoverageKey(
		"config",
		"path",
		child+"\x00descendant",
	)
	data.Meta.Collection.CoverageKeys = append(
		data.Meta.Collection.CoverageKeys,
		grandchild,
	)
	data.Meta.Collection.Outcomes = append(
		data.Meta.Collection.Outcomes,
		ingest.CollectionOutcome{
			Collector: "config", CoverageKey: grandchild,
			ParentCoverageKey: child, Target: "/home/example/project/descendant",
			Method: "config_discovery", State: ingest.OutcomeComplete,
		},
	)
	data.Meta.Collection.State = ingest.AggregateOutcomeState(
		data.Meta.Collection.Outcomes,
	)
	for i := range data.Graph.Nodes {
		data.Graph.Nodes[i].ObservationDomains = []string{grandchild}
	}
	for i := range data.Graph.Edges {
		data.Graph.Edges[i].ObservationDomains = []string{grandchild}
	}

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"meta.collection.outcomes[4].parent_coverage_key",
	)
}

func TestValidatorRejectsParentOnInstructionRoot(t *testing.T) {
	data, root, child := validInstructionRootDataFor(
		ingest.InstructionMethodDeep,
		ingest.OutcomePartial,
	)
	for i := range data.Meta.Collection.Outcomes {
		if data.Meta.Collection.Outcomes[i].CoverageKey == root {
			data.Meta.Collection.Outcomes[i].ParentCoverageKey = child
		}
	}
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"meta.collection.outcomes[0].parent_coverage_key",
	)
}

func TestValidatorRequiresExactRootsForConfigCollection(t *testing.T) {
	data, _, _ := validInstructionRootData(ingest.OutcomeComplete)
	data.Meta.Collection.AuthoritativeRoots = data.Meta.Collection.AuthoritativeRoots[:1]
	data.Meta.Collection.CoverageKeys = data.Meta.Collection.CoverageKeys[:2]
	data.Meta.Collection.Outcomes = data.Meta.Collection.Outcomes[:2]
	data.Meta.Collection.State = ingest.AggregateOutcomeState(data.Meta.Collection.Outcomes)

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"meta.collection.authoritative_roots",
	)
}

func TestValidatorAllowsFailedConfigSubreportAlongsideMCP(t *testing.T) {
	data := validIngestData()
	configRoot := ingest.CollectorRootCoverageKey("config")
	data.Meta.Collector = "scan"
	data.Meta.Collection.CoverageKeys = append(
		data.Meta.Collection.CoverageKeys,
		configRoot,
	)
	data.Meta.Collection.Outcomes = append(
		data.Meta.Collection.Outcomes,
		ingest.CollectionOutcome{
			Collector: "config", CoverageKey: configRoot,
			Target: "config", Method: "collect",
			State: ingest.OutcomeFailed, Error: "config collection failed",
		},
	)
	data.Meta.Collection.State = ingest.AggregateOutcomeState(data.Meta.Collection.Outcomes)

	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("failed config subreport rejected: %v", err)
	}
}

func validInstructionRootData(rootState ingest.OutcomeState) (*ingest.IngestData, string, string) {
	data := validIngestData()
	data.Meta.Collector = "config"
	root := ingest.CanonicalCoverageKey("config", "instruction-deep", "/home/example")
	child := ingest.CanonicalCoverageKey("config", "instruction-source", root+"\x00/home/example/project/AGENTS.md")
	exactUser := ingest.CanonicalCoverageKey("config", "instruction-exact-user", "/home/example")
	exactProject := ingest.CanonicalCoverageKey("config", "instruction-exact-project", "/home/example/project")
	contract := ingest.CurrentInstructionRegistryContract()
	data.Meta.Collection = &ingest.CollectionReport{
		CoverageKeys: []string{root, child, exactUser, exactProject},
		AuthoritativeRoots: []ingest.CoverageRoot{
			{
				CoverageKey:       root,
				ChildCoverageKeys: []string{child},
				RegistryContract:  &contract,
			},
			{CoverageKey: exactUser, RegistryContract: &contract},
			{CoverageKey: exactProject, RegistryContract: &contract},
		},
		Outcomes: []ingest.CollectionOutcome{
			{
				Collector: "config", CoverageKey: root, Target: "/home/example",
				Method: ingest.InstructionMethodDeep, State: rootState,
			},
			{
				Collector: "config", CoverageKey: child, ParentCoverageKey: root,
				Target: "/home/example/project/AGENTS.md", Method: ingest.InstructionMethodSource,
				State: ingest.OutcomeComplete, Items: len(data.Graph.Nodes),
			},
			{
				Collector: "config", CoverageKey: exactUser,
				Target: "/home/example", Method: ingest.InstructionMethodExactUser,
				State: ingest.OutcomeComplete,
			},
			{
				Collector: "config", CoverageKey: exactProject,
				Target: "/home/example/project", Method: ingest.InstructionMethodExactProject,
				State: ingest.OutcomeComplete,
			},
		},
	}
	data.Meta.Collection.State = ingest.AggregateOutcomeState(data.Meta.Collection.Outcomes)
	for i := range data.Graph.Nodes {
		data.Graph.Nodes[i].ObservationDomains = []string{child}
	}
	for i := range data.Graph.Edges {
		data.Graph.Edges[i].ObservationDomains = []string{child}
	}
	return data, root, child
}

func validInstructionRootDataFor(
	method string,
	rootState ingest.OutcomeState,
) (*ingest.IngestData, string, string) {
	data, deepRoot, child := validInstructionRootData(ingest.OutcomeComplete)
	if method == ingest.InstructionMethodDeep {
		for i := range data.Meta.Collection.Outcomes {
			if data.Meta.Collection.Outcomes[i].CoverageKey == deepRoot {
				data.Meta.Collection.Outcomes[i].State = rootState
			}
		}
		data.Meta.Collection.State = ingest.AggregateOutcomeState(data.Meta.Collection.Outcomes)
		return data, deepRoot, child
	}

	selectedRoot := ""
	for i := range data.Meta.Collection.Outcomes {
		outcome := &data.Meta.Collection.Outcomes[i]
		switch {
		case outcome.CoverageKey == deepRoot:
			outcome.State = ingest.OutcomeComplete
		case outcome.Method == method:
			outcome.State = rootState
			selectedRoot = outcome.CoverageKey
		case outcome.CoverageKey == child:
			outcome.ParentCoverageKey = selectedRoot
		}
	}
	if selectedRoot == "" {
		panic("unsupported instruction root method in test")
	}
	for i := range data.Meta.Collection.AuthoritativeRoots {
		root := &data.Meta.Collection.AuthoritativeRoots[i]
		switch root.CoverageKey {
		case deepRoot:
			root.ChildCoverageKeys = nil
		case selectedRoot:
			root.ChildCoverageKeys = []string{child}
		}
	}
	for i := range data.Meta.Collection.Outcomes {
		if data.Meta.Collection.Outcomes[i].CoverageKey == child {
			data.Meta.Collection.Outcomes[i].ParentCoverageKey = selectedRoot
		}
	}
	data.Meta.Collection.State = ingest.AggregateOutcomeState(data.Meta.Collection.Outcomes)
	return data, selectedRoot, child
}

func TestValidatorRequiresCompleteV2Metadata(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*ingest.IngestData)
		path string
	}{
		{"collection", func(data *ingest.IngestData) { data.Meta.Collection = nil }, "meta.collection"},
		{"ruleset", func(data *ingest.IngestData) { data.Meta.Ruleset = nil }, "meta.ruleset"},
		{"identity schemes", func(data *ingest.IngestData) { data.Meta.IdentitySchemes = nil }, "meta.identity_schemes"},
		{"fact ownership", func(data *ingest.IngestData) { data.Graph.Nodes[0].ObservationDomains = nil }, "graph.nodes[0].observation_domains"},
		{"edge source kind", func(data *ingest.IngestData) { data.Graph.Edges[0].SourceKind = "" }, "graph.edges[0].source_kind"},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := validIngestData()
			test.edit(data)
			assertValidationError(t, NewValidator().Validate(data), test.path)
		})
	}
}

func TestValidatorRejectsLegacyPropertyAliases(t *testing.T) {
	for alias := range forbiddenPropertyAliases {
		t.Run(alias, func(t *testing.T) {
			data := validIngestData()
			data.Graph.Nodes[1].Properties[alias] = true
			assertValidationError(
				t,
				NewValidator().Validate(data),
				"graph.nodes[1].properties."+alias,
			)
		})
	}
}

func TestValidatorRejectsRemovedGraphCompatibilityProperties(t *testing.T) {
	for _, property := range removedGraphProperties {
		t.Run(property, func(t *testing.T) {
			data := validIngestData()
			data.Graph.Nodes[0].Properties[property] = true
			assertValidationError(
				t,
				NewValidator().Validate(data),
				"graph.nodes[0].properties."+property,
			)
		})
	}
}

func TestValidatorRequiresHashedArgvStdioIdentity(t *testing.T) {
	t.Run("metadata", func(t *testing.T) {
		data := validIngestData()
		data.Meta.IdentitySchemes[0].Scheme = "mcp_stdio_unsupported"
		data.Meta.IdentitySchemes[0].Version = 2
		assertValidationError(
			t,
			NewValidator().Validate(data),
			"meta.identity_schemes[0]",
		)
	})
	t.Run("node", func(t *testing.T) {
		data := validIngestData()
		data.Graph.Nodes[0].Properties["transport"] = "stdio"
		delete(data.Graph.Nodes[0].Properties, "endpoint")
		data.Graph.Nodes[0].Properties["id_scheme"] = "unordered"
		assertValidationError(
			t,
			NewValidator().Validate(data),
			"graph.nodes[0].properties.id_scheme",
		)
	})
}

func TestValidatorRequiresCurrentStdioParentAndChildIDs(t *testing.T) {
	currentData := func() *ingest.IngestData {
		data := validIngestData()
		identity := ingest.ResolveMCPServerIdentity(
			"stdio",
			"npx",
			"-y",
			"@modelcontextprotocol/server-postgres",
		)
		parentID := identity.ObjectID
		childID := ingest.ComputeNodeID("MCPTool", parentID, "tool")
		data.Graph.Nodes[0].ID = parentID
		data.Graph.Nodes[0].Properties["transport"] = "stdio"
		delete(data.Graph.Nodes[0].Properties, "endpoint")
		data.Graph.Nodes[0].Properties["command"] = "npx"
		data.Graph.Nodes[0].Properties["arg_hashes"] = identity.ArgumentHashes
		data.Graph.Nodes[0].Properties["arg_count"] = len(identity.ArgumentHashes)
		data.Graph.Nodes[0].Properties["id_scheme"] = ingest.MCPStdioIdentitySchemeV1
		data.Graph.Nodes[1].ID = childID
		data.Graph.Edges[0].Source = parentID
		data.Graph.Edges[0].Target = childID
		return data
	}

	if err := NewValidator().Validate(currentData()); err != nil {
		t.Fatalf("current stdio identities rejected: %v", err)
	}
	t.Run("parent", func(t *testing.T) {
		data := currentData()
		data.Graph.Nodes[0].ID = "sha256:former-parent"
		data.Graph.Edges[0].Source = data.Graph.Nodes[0].ID
		assertValidationError(t, NewValidator().Validate(data), "graph.nodes[0].id")
	})
	t.Run("child", func(t *testing.T) {
		data := currentData()
		data.Graph.Nodes[1].ID = "sha256:former-child"
		data.Graph.Edges[0].Target = data.Graph.Nodes[1].ID
		assertValidationError(t, NewValidator().Validate(data), "graph.edges[0].target")
	})
}

func TestValidatorRejectsRawOrUnverifiableStdioArgv(t *testing.T) {
	currentData := func() *ingest.IngestData {
		data := validIngestData()
		identity := ingest.ResolveMCPServerIdentity("stdio", "node", "server.js", "--token=secret")
		data.Graph.Nodes[0].ID = identity.ObjectID
		data.Graph.Nodes[0].Properties["transport"] = "stdio"
		delete(data.Graph.Nodes[0].Properties, "endpoint")
		data.Graph.Nodes[0].Properties["command"] = "node"
		data.Graph.Nodes[0].Properties["arg_hashes"] = identity.ArgumentHashes
		data.Graph.Nodes[0].Properties["arg_count"] = len(identity.ArgumentHashes)
		data.Graph.Nodes[0].Properties["id_scheme"] = ingest.MCPStdioIdentitySchemeV1
		data.Graph.Nodes[1].ID = ingest.ComputeNodeID("MCPTool", identity.ObjectID, "tool")
		data.Graph.Edges[0].Source = identity.ObjectID
		data.Graph.Edges[0].Target = data.Graph.Nodes[1].ID
		return data
	}

	if err := NewValidator().Validate(currentData()); err != nil {
		t.Fatalf("hashed argv contract rejected: %v", err)
	}
	t.Run("raw args", func(t *testing.T) {
		data := currentData()
		data.Graph.Nodes[0].Properties["args"] = []string{"--token=secret"}
		assertValidationError(t, NewValidator().Validate(data), "graph.nodes[0].properties.args")
	})
	t.Run("missing hashes", func(t *testing.T) {
		data := currentData()
		delete(data.Graph.Nodes[0].Properties, "arg_hashes")
		assertValidationError(t, NewValidator().Validate(data), "graph.nodes[0].properties.arg_hashes")
	})
	t.Run("null hashes", func(t *testing.T) {
		data := currentData()
		data.Graph.Nodes[0].Properties["arg_hashes"] = nil
		data.Graph.Nodes[0].Properties["arg_count"] = 0
		assertValidationError(t, NewValidator().Validate(data), "graph.nodes[0].properties.arg_hashes")
	})
	t.Run("non canonical hash", func(t *testing.T) {
		data := currentData()
		data.Graph.Nodes[0].Properties["arg_hashes"] = []string{"sha256:not-a-digest"}
		data.Graph.Nodes[0].Properties["arg_count"] = 1
		assertValidationError(t, NewValidator().Validate(data), "graph.nodes[0].properties.arg_hashes[0]")
	})
	t.Run("count mismatch", func(t *testing.T) {
		data := currentData()
		data.Graph.Nodes[0].Properties["arg_count"] = 1
		assertValidationError(t, NewValidator().Validate(data), "graph.nodes[0].properties.arg_count")
	})
	t.Run("missing count", func(t *testing.T) {
		data := currentData()
		delete(data.Graph.Nodes[0].Properties, "arg_count")
		assertValidationError(t, NewValidator().Validate(data), "graph.nodes[0].properties.arg_count")
	})
	t.Run("id mismatch", func(t *testing.T) {
		data := currentData()
		data.Graph.Nodes[0].ID = ingest.ComputeNodeID("wrong", "stdio-server")
		data.Graph.Edges[0].Source = data.Graph.Nodes[0].ID
		assertValidationError(t, NewValidator().Validate(data), "graph.nodes[0].id")
	})
}

func TestValidatorRejectsRawMCPTransportPropertiesWithoutTrustingTransport(t *testing.T) {
	for _, test := range []struct {
		name      string
		transport any
		set       bool
	}{
		{name: "http", transport: "http", set: true},
		{name: "omitted"},
		{name: "ill typed", transport: map[string]any{"type": "stdio"}, set: true},
	} {
		t.Run("args with "+test.name+" transport", func(t *testing.T) {
			data := validIngestData()
			if test.set {
				data.Graph.Nodes[0].Properties["transport"] = test.transport
			} else {
				delete(data.Graph.Nodes[0].Properties, "transport")
			}
			if test.transport == "http" {
				data.Graph.Nodes[0].Properties["endpoint"] = "https://mcp.example/api"
			}
			data.Graph.Nodes[0].Properties["args"] = []string{"--token=secret"}
			assertValidationError(
				t,
				NewValidator().Validate(data),
				"graph.nodes[0].properties.args",
			)
		})
	}

	for _, test := range []struct {
		property string
		value    any
	}{
		{property: "args", value: []string{"--token=secret"}},
		{property: "env", value: map[string]string{"API_KEY": "secret"}},
		{property: "headers", value: map[string]string{"Authorization": "Bearer secret"}},
		{property: "url", value: "https://mcp.example/api?token=secret"},
	} {
		t.Run("raw "+test.property, func(t *testing.T) {
			data := validIngestData()
			data.Graph.Nodes[0].Properties[test.property] = test.value
			assertValidationError(
				t,
				NewValidator().Validate(data),
				"graph.nodes[0].properties."+test.property,
			)
		})
	}
}

func TestValidatorRequiresCanonicalSanitizedHTTPMCPEndpoint(t *testing.T) {
	for _, test := range []struct {
		name     string
		endpoint any
		set      bool
	}{
		{name: "missing"},
		{name: "ill typed", endpoint: []string{"https://mcp.example/api"}, set: true},
		{name: "userinfo", endpoint: "https://user:secret@mcp.example/api", set: true},
		{name: "query", endpoint: "https://mcp.example/api?token=secret", set: true},
		{name: "fragment", endpoint: "https://mcp.example/api#secret", set: true},
		{name: "relative", endpoint: "/api?token=secret", set: true},
		{name: "malformed", endpoint: "https://%zz", set: true},
		{name: "invalid raw text", endpoint: "token=secret", set: true},
		{name: "invalid placeholder", endpoint: ingest.InvalidHTTPEndpointDisplay, set: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := validIngestData()
			data.Graph.Nodes[0].Properties["transport"] = "http"
			if test.set {
				data.Graph.Nodes[0].Properties["endpoint"] = test.endpoint
			} else {
				delete(data.Graph.Nodes[0].Properties, "endpoint")
			}
			assertValidationError(
				t,
				NewValidator().Validate(data),
				"graph.nodes[0].properties.endpoint",
			)
		})
	}
}

func TestValidatorSanitizesMCPEndpointWithoutTrustingTransport(t *testing.T) {
	for _, test := range []struct {
		name      string
		transport any
		set       bool
	}{
		{name: "omitted"},
		{name: "ill typed", transport: map[string]any{"type": "http"}, set: true},
		{name: "noncanonical string", transport: "HTTP", set: true},
	} {
		t.Run("raw endpoint with "+test.name+" transport", func(t *testing.T) {
			data := validIngestData()
			if test.set {
				data.Graph.Nodes[0].Properties["transport"] = test.transport
			} else {
				delete(data.Graph.Nodes[0].Properties, "transport")
			}
			data.Graph.Nodes[0].Properties["endpoint"] = "https://mcp.example/api?token=secret"
			assertValidationError(
				t,
				NewValidator().Validate(data),
				"graph.nodes[0].properties.endpoint",
			)
		})

		t.Run("clean endpoint still rejects "+test.name+" transport", func(t *testing.T) {
			data := validIngestData()
			if test.set {
				data.Graph.Nodes[0].Properties["transport"] = test.transport
			} else {
				delete(data.Graph.Nodes[0].Properties, "transport")
			}
			data.Graph.Nodes[0].Properties["endpoint"] = "https://mcp.example/api"
			assertValidationError(
				t,
				NewValidator().Validate(data),
				"graph.nodes[0].properties.transport",
			)
		})
	}
}

func TestValidatorAcceptsSanitizedHTTPMCPEndpointWithRedactionMarkers(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].Properties["transport"] = "http"
	data.Graph.Nodes[0].Properties["endpoint"] = "https://mcp.example/api"
	data.Graph.Nodes[0].Properties["endpoint_userinfo_redacted"] = true
	data.Graph.Nodes[0].Properties["endpoint_query_redacted"] = true
	data.Graph.Nodes[0].Properties["endpoint_fragment_redacted"] = true

	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("canonical sanitized HTTP MCP endpoint rejected: %v", err)
	}
}

func TestValidatorRejectsBadType(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.Type = "wrong"
	err := v.Validate(data)
	assertValidationError(t, err, "meta.type")
}

func TestValidatorRejectsBadCollector(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.Collector = "unknown"
	err := v.Validate(data)
	assertValidationError(t, err, "meta.collector")
}

func TestValidatorRejectsEmptyScanID(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.ScanID = ""
	err := v.Validate(data)
	assertValidationError(t, err, "meta.scan_id")
}

func TestValidatorRejectsEmptyNodeID(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes[0].ID = ""
	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[0].id")
}

func TestValidatorRejectsEmptyNodeKinds(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes[0].Kinds = nil
	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[0].kinds")
}

func TestValidatorRejectsInvalidNodeKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes[0].Kinds = []string{"FakeNode"}
	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[0].kinds[0]")
}

func TestValidatorRejectsConflictingConcreteKindsInOneNode(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{{
		ID:    "shared-role",
		Kinds: []string{"MCPServer", "MCPTool"},
		Properties: map[string]any{
			"auth_method":    "unknown",
			"auth_assurance": "unknown",
			"auth_evidence":  "unknown",
		},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	}}
	data.Graph.Edges = []ingest.Edge{{
		Source:             "shared-role",
		Target:             "shared-role",
		Kind:               "PROVIDES_TOOL",
		SourceKind:         "MCPServer",
		TargetKind:         "MCPTool",
		Properties:         map[string]any{"risk_weight": 0.1},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	}}

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[0].kinds",
	)
}

func TestValidatorRejectsConflictingConcreteKindsAcrossDuplicateRows(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[1].ID = data.Graph.Nodes[0].ID
	data.Graph.Edges[0].Target = data.Graph.Nodes[0].ID

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[1].kinds",
	)
}

func TestValidatorAcceptsDocumentedUmbrellaAndRepeatedConcreteRows(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes,
		ingest.Node{
			ID:                 "sha256:gateway",
			Kinds:              []string{"LiteLLMGateway", "AIService"},
			Properties:         map[string]any{"name": "gateway"},
			ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
		},
		ingest.Node{
			ID:    data.Graph.Nodes[0].ID,
			Kinds: []string{"MCPServer"},
			Properties: map[string]any{
				"name": "same server", "transport": "http", "endpoint": "https://mcp.example",
				"auth_method":    "unknown",
				"auth_assurance": "unknown", "auth_evidence": "unknown",
			},
			ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
		},
	)

	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("valid umbrella/repeated concrete rows rejected: %v", err)
	}
}

func TestValidatorRejectsUndocumentedUmbrellaCompanion(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].Kinds = []string{"MCPServer", "AIService"}
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[0].kinds",
	)
}

func TestValidatorRejectsCredentialWithoutValueHash(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes, ingest.Node{
		ID:                 "sha256:cred",
		Kinds:              []string{"Credential"},
		Properties:         map[string]any{"name": "API_KEY"},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	})
	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[2].properties.value_hash")
}

func TestValidatorAcceptsCredentialWithValueHash(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes, ingest.Node{
		ID:    "sha256:cred",
		Kinds: []string{"Credential"},
		Properties: map[string]any{
			"name": "API_KEY", "value_hash": "sha256:abc",
			"merge_key": "value_hash", "identity_basis": "value_hash",
			"material_status": "observed", "exposure_status": "exposed",
		},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	})
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected credential with value_hash to validate, got: %v", err)
	}
}

func TestValidatorRejectsCredentialWithoutCanonicalMergeKey(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes, ingest.Node{
		ID:    "sha256:cred",
		Kinds: []string{"Credential"},
		Properties: map[string]any{
			"name": "API_KEY", "value_hash": "sha256:abc",
			"identity_basis": "value_hash", "material_status": "observed",
			"exposure_status": "exposed",
		},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	})
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[2].properties.merge_key",
	)
}

func TestValidatorRejectsEmptyEdgeSource(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].Source = ""
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].source")
}

func TestValidatorRejectsInvalidEdgeKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].Kind = "FAKE_EDGE"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].kind")
}

func TestValidatorRejectsCompositeEdgeKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].Kind = "CAN_REACH"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].kind")
}

func TestValidatorRejectsInvalidEdgeSourceKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].SourceKind = "MCPServer) WITH edge MATCH (z) DETACH DELETE z //"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].source_kind")
}

func TestValidatorRejectsInvalidEdgeTargetKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].TargetKind = "MCPTool {x:1}) DETACH DELETE n //"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].target_kind")
}

func TestValidatorAcceptsValidExplicitEdgeKinds(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].SourceKind = "MCPServer"
	data.Graph.Edges[0].TargetKind = "MCPTool"
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected explicit valid edge kinds to validate, got: %v", err)
	}
}

func TestValidatorRejectsIncompatibleSourceKind(t *testing.T) {
	// MCPTool is a valid node label but not a valid *source* for PROVIDES_TOOL
	// (which must be MCPServer -> MCPTool). AH-UI-30: reject the inverted role.
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].SourceKind = "MCPTool"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].source_kind")
}

func TestValidatorRejectsIncompatibleTargetKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].TargetKind = "MCPServer"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].target_kind")
}

func TestValidatorAcceptsCompatibleEndpointKinds(t *testing.T) {
	// PROVIDES_RESOURCE permits multiple valid sources; JupyterServer is one.
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes,
		ingest.Node{ID: "sha256:jup", Kinds: []string{"JupyterServer"}, Properties: map[string]any{"name": "j"}, ObservationDomains: data.Graph.Nodes[0].ObservationDomains},
		ingest.Node{ID: "sha256:res", Kinds: []string{"MCPResource"}, Properties: map[string]any{"name": "r"}, ObservationDomains: data.Graph.Nodes[0].ObservationDomains},
	)
	data.Graph.Edges = append(data.Graph.Edges, ingest.Edge{
		Source: "sha256:jup", Target: "sha256:res", Kind: "PROVIDES_RESOURCE",
		SourceKind: "JupyterServer", TargetKind: "MCPResource",
		Properties:         map[string]any{"risk_weight": 0.2},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	})
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected compatible endpoint kinds to validate, got: %v", err)
	}
}

func TestValidatorAcceptsExplicitAlternateEndpointKinds(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{
		{ID: "sha256:jup", Kinds: []string{"JupyterServer", "AIService"}, Properties: map[string]any{"name": "j"}, ObservationDomains: data.Graph.Nodes[0].ObservationDomains},
		{ID: "sha256:res", Kinds: []string{"MCPResource"}, Properties: map[string]any{"name": "r"}, ObservationDomains: data.Graph.Nodes[0].ObservationDomains},
	}
	data.Graph.Edges = []ingest.Edge{{
		Source: "sha256:jup", Target: "sha256:res", Kind: "PROVIDES_RESOURCE",
		SourceKind: "JupyterServer", TargetKind: "MCPResource",
		Properties:         map[string]any{"risk_weight": 0.2},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	}}

	if err := v.Validate(data); err != nil {
		t.Fatalf("expected omitted kinds to resolve from actual nodes, got: %v", err)
	}
}

func TestValidatorAcceptsConcreteExposesEndpointKinds(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{
		{ID: "sha256:webui", Kinds: []string{"OpenWebUIInstance", "AIService"}, Properties: map[string]any{"name": "webui"}, ObservationDomains: data.Graph.Nodes[0].ObservationDomains},
		{ID: "sha256:ollama", Kinds: []string{"OllamaInstance", "AIService"}, Properties: map[string]any{"name": "ollama"}, ObservationDomains: data.Graph.Nodes[0].ObservationDomains},
	}
	data.Graph.Edges = []ingest.Edge{{
		Source:             "sha256:webui",
		Target:             "sha256:ollama",
		Kind:               "EXPOSES",
		SourceKind:         "OpenWebUIInstance",
		TargetKind:         "OllamaInstance",
		Properties:         map[string]any{"risk_weight": 0.3},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	}}

	if err := v.Validate(data); err != nil {
		t.Fatalf("expected producer's concrete EXPOSES labels to validate, got: %v", err)
	}
}

func TestValidatorRejectsDeclaredKindThatDoesNotMatchReferencedNode(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].SourceKind = "MCPServer"
	data.Graph.Edges[0].TargetKind = "MCPTool"
	// Both declared kinds are valid for PROVIDES_TOOL, but the referenced
	// source node does not actually carry the declared MCPServer label.
	data.Graph.Nodes[0].Kinds = []string{"MCPTool"}

	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].source_kind")
}

func TestValidatorRejectsMissingReferencedNode(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].Target = "sha256:not-in-artifact"

	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].target")
}

func TestValidatorAcceptsReferencedUmbrellaLabel(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{
		{
			ID:                 "sha256:gateway",
			Kinds:              []string{"LiteLLMGateway", "AIService"},
			Properties:         map[string]any{"name": "gateway"},
			ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
		},
		{
			ID:    "sha256:credential",
			Kinds: []string{"Credential"},
			Properties: map[string]any{
				"name": "key", "value_hash": "abc",
				"merge_key": "value_hash", "identity_basis": "value_hash",
				"material_status": "observed", "exposure_status": "exposed",
			},
			ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
		},
	}
	data.Graph.Edges = []ingest.Edge{{
		Source: "sha256:gateway", Target: "sha256:credential",
		Kind: "EXPOSES_CREDENTIAL", SourceKind: "AIService", TargetKind: "Credential",
		Properties:         map[string]any{"risk_weight": 0.1},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	}}

	if err := v.Validate(data); err != nil {
		t.Fatalf("expected actual AIService umbrella label to validate, got: %v", err)
	}
}

func TestValidatorRejectsRawEdgeMissingRiskWeight(t *testing.T) {
	data := validIngestData()
	delete(data.Graph.Edges[0].Properties, "risk_weight")
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.edges[0].properties.risk_weight",
	)
}

func TestValidatorRejectsRawEdgeInvalidRiskWeight(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
	}{
		{"string", "0.1"},
		{"bool", true},
		{"nan", math.NaN()},
		{"positive infinity", math.Inf(1)},
		{"negative infinity", math.Inf(-1)},
		{"negative", -0.1},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := validIngestData()
			data.Graph.Edges[0].Properties["risk_weight"] = test.value
			assertValidationError(
				t,
				NewValidator().Validate(data),
				"graph.edges[0].properties.risk_weight",
			)
		})
	}
}

func TestValidatorAcceptsRawEdgeRiskWeight(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
	}{
		{"zero float", 0.0},
		{"positive float", 0.75},
		{"json number", json.Number("0.4")},
		{"native int", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := validIngestData()
			data.Graph.Edges[0].Properties["risk_weight"] = test.value
			if err := NewValidator().Validate(data); err != nil {
				t.Fatalf("expected valid risk_weight %v to pass, got: %v", test.value, err)
			}
		})
	}
}

func TestValidatorCollectsAllErrors(t *testing.T) {
	v := NewValidator()
	data := &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:   ingest.CurrentVersion,
			Type:      "wrong",
			Collector: "bad",
			ScanID:    "",
		},
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{{ID: "", Kinds: nil}},
			Edges: []ingest.Edge{{Source: "", Target: "", Kind: "FAKE"}},
		},
	}
	err := v.Validate(data)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
	if len(ve.Errors) < 7 {
		t.Errorf("expected at least 7 errors, got %d: %+v", len(ve.Errors), ve.Errors)
	}
}

func TestValidatorAcceptsEmptyGraph(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{}
	data.Graph.Edges = []ingest.Edge{}
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected no error for empty graph, got: %v", err)
	}
}

func TestValidatorRejectsNullGraphCollections(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes = nil
	data.Graph.Edges = nil
	err := NewValidator().Validate(data)
	assertValidationError(t, err, "graph.nodes")
	assertValidationError(t, err, "graph.edges")
}

func TestValidationError_Error(t *testing.T) {
	ve := &ValidationError{
		Errors: []FieldError{
			{Path: "meta.version", Message: "must be 2"},
			{Path: "meta.type", Message: "must be 'agenthound-ingest'"},
			{Path: "meta.scan_id", Message: "must not be empty"},
		},
	}
	got := ve.Error()
	if got != "validation failed: 3 errors" {
		t.Errorf("Error() = %q, want %q", got, "validation failed: 3 errors")
	}
}

func assertValidationError(t *testing.T, err error, expectedPath string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	for _, fe := range ve.Errors {
		if fe.Path == expectedPath {
			return
		}
	}
	t.Errorf("expected error at path %q, got errors: %+v", expectedPath, ve.Errors)
}

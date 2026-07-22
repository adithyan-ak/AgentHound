package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHandleOpenAPIDocs(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/docs/openapi.yaml", nil)
	HandleOpenAPIDocs(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/yaml" {
		t.Fatalf("expected Content-Type application/yaml, got %q", ct)
	}
	body := w.Body.String()
	if body == "" {
		t.Fatal("expected non-empty body")
	}
	if !strings.Contains(body, "openapi:") {
		t.Fatal("body does not contain 'openapi:' marker")
	}
}

func TestOpenAPIProjectionAwareResponseContracts(t *testing.T) {
	var spec map[string]any
	if err := yaml.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("parse embedded OpenAPI: %v", err)
	}

	schemas := nestedMap(t, spec, "components", "schemas")
	requireSchemaFields(t, schemas, "ProjectionIdentity", "scan_id", "revision")
	requireSchemaFields(
		t,
		schemas,
		"GraphStats",
		"node_counts",
		"edge_counts",
		"total_nodes",
		"total_edges",
		"projection",
	)
	requireSchemaFields(
		t,
		schemas,
		"PageMetadata",
		"offset",
		"limit",
		"total",
		"has_more",
		"complete",
		"revision",
		"projection",
	)
	requireSchemaFields(t, schemas, "PathResponse", "paths", "metadata", "projection")
	requireSchemaFields(t, schemas, "PreBuiltResult", "query", "rows", "projection")
	requireSchemaFields(t, schemas, "IngestMetaV4", "identity", "collection")
	requireSchemaFields(t, schemas, "CollectionIdentityV4", "collection_point_id", "network_context_id", "quality", "network_class", "evidence", "network_evidence")
	requireSchemaFields(t, schemas, "IngestCollectionV4", "state", "coverage_keys", "outcomes")
	requireSchemaFields(t, schemas, "IngestResult", "collection", "identity")
	ingestResponses := nestedMap(t, spec, "paths", "/ingest", "post", "responses")
	for _, status := range []string{"200", "400", "403", "500", "503"} {
		if _, ok := ingestResponses[status]; !ok {
			t.Errorf("POST /ingest does not document response %s", status)
		}
	}

	paths := nestedMap(t, spec, "paths")
	for _, contract := range []struct {
		path   string
		method string
	}{
		{"/graph/stats", "get"},
		{"/graph/search", "get"},
		{"/graph/nodes", "get"},
		{"/graph/nodes/{id}", "get"},
		{"/graph/nodes/{id}/neighborhood", "get"},
		{"/graph/nodes/{id}/blast-radius", "get"},
		{"/graph/edges", "get"},
		{"/analysis/shortest-path", "post"},
		{"/analysis/all-paths", "post"},
		{"/analysis/weighted-path", "post"},
		{"/analysis/topology/shortest-path", "post"},
		{"/analysis/topology/all-paths", "post"},
		{"/analysis/topology/weighted-path", "post"},
		{"/analysis/prebuilt/{id}", "get"},
	} {
		responses := nestedMap(t, paths, contract.path, contract.method, "responses")
		if _, ok := responses["409"]; !ok {
			t.Errorf("%s %s does not document PROJECTION_CONFLICT", contract.method, contract.path)
		}
	}
}

func TestOpenAPIRuntimeParityContracts(t *testing.T) {
	var spec map[string]any
	if err := yaml.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("parse embedded OpenAPI: %v", err)
	}

	schemas := nestedMap(t, spec, "components", "schemas")
	requireSchemaFields(
		t,
		schemas,
		"ScanPageMetadata",
		"offset",
		"limit",
		"total",
		"has_more",
		"complete",
		"revision",
	)
	scanPageProperties := nestedMap(t, schemas, "ScanPageMetadata", "properties")
	if _, ok := scanPageProperties["projection"]; ok {
		t.Fatal("ScanPageMetadata must not require graph projection identity")
	}
	scanListPage := nestedMap(
		t,
		schemas,
		"ScanListResponse",
		"properties",
		"page",
	)
	if got := scanListPage["$ref"]; got != "#/components/schemas/ScanPageMetadata" {
		t.Fatalf("ScanListResponse.page ref = %v, want ScanPageMetadata", got)
	}

	paths := nestedMap(t, spec, "paths")
	searchLimit := operationParameter(t, paths, "/graph/search", "get", "limit")
	requireIntegerContract(
		t,
		nestedMap(t, searchLimit, "schema"),
		"default",
		defaultGraphSearchLimit,
	)
	requireIntegerContract(
		t,
		nestedMap(t, searchLimit, "schema"),
		"maximum",
		maxGraphSearchLimit,
	)

	blastHops := operationParameter(
		t,
		paths,
		"/graph/nodes/{id}/blast-radius",
		"get",
		"max_hops",
	)
	requireIntegerContract(
		t,
		nestedMap(t, blastHops, "schema"),
		"default",
		defaultBlastRadiusMaxHops,
	)

	neighborhood := nestedMap(
		t,
		paths,
		"/graph/nodes/{id}/neighborhood",
		"get",
	)
	if hasOperationParameter(t, neighborhood, "limit") {
		t.Fatal("neighborhood documents a limit parameter that runtime ignores")
	}
}

func TestServedOpenAPICampaignParity(t *testing.T) {
	recorder := httptest.NewRecorder()
	HandleOpenAPIDocs(
		recorder,
		httptest.NewRequest(http.MethodGet, "/api/v1/docs", nil),
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("served OpenAPI status = %d", recorder.Code)
	}

	var spec map[string]any
	if err := yaml.Unmarshal(recorder.Body.Bytes(), &spec); err != nil {
		t.Fatalf("parse served OpenAPI: %v", err)
	}
	schemas := nestedMap(t, spec, "components", "schemas")
	requireSchemaFields(
		t,
		schemas,
		"FindingVerification",
		"scenario_id",
		"scenario_version",
		"campaign_run_id",
		"verified_at",
		"oracle_type",
		"outcome",
		"control_stage",
		"control_status",
		"control_resource_addressed",
		"authed_stage",
		"authed_status",
		"authed_resource_addressed",
		"cleanup_status",
	)
	requireSchemaFields(
		t,
		schemas,
		"CampaignWitness",
		"schema_version",
		"topology_normalization_version",
		"publication_revision",
		"predicted_edge_kind",
		"agent_id",
		"agent_kind",
		"credential_id",
		"credential_kind",
		"credential_value_hash",
		"credential_merge_key",
		"server_id",
		"server_kind",
		"resource_id",
		"resource_kind",
		"resource_identity_input",
		"evidence_node_ids",
		"evidence_node_kinds",
	)
	requireSchemaFields(t, schemas, "FindingWitnessResponse", "witness", "projection")

	evidenceProperties := nestedMap(t, schemas, "FindingEvidence", "properties")
	verification := nestedMap(t, evidenceProperties, "verification")
	if got := verification["$ref"]; got != "#/components/schemas/FindingVerification" {
		t.Fatalf("FindingEvidence.verification ref = %v", got)
	}
	evidenceRequired, ok := nestedMap(t, schemas, "FindingEvidence")["required"].([]any)
	if !ok {
		t.Fatal("FindingEvidence.required is not an array")
	}
	if containsString(evidenceRequired, "verification") {
		t.Fatal("FindingEvidence.verification must remain optional")
	}
	state := nestedMap(t, evidenceProperties, "state")
	enum, ok := state["enum"].([]any)
	if !ok || !containsString(enum, "verified") {
		t.Fatalf("FindingEvidence.state enum = %v, want verified", state["enum"])
	}

	paths := nestedMap(t, spec, "paths")
	responses := nestedMap(
		t,
		paths,
		"/analysis/findings/{id}/witness",
		"get",
		"responses",
	)
	for _, status := range []string{"200", "400", "404", "409"} {
		if _, ok := responses[status]; !ok {
			t.Errorf("witness export does not document %s", status)
		}
	}
	successSchema := nestedMap(
		t,
		responses,
		"200",
		"content",
		"application/json",
		"schema",
	)
	if got := successSchema["$ref"]; got != "#/components/schemas/FindingWitnessResponse" {
		t.Fatalf("witness 200 schema ref = %v", got)
	}
}

func containsString(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func requireSchemaFields(
	t *testing.T,
	schemas map[string]any,
	schemaName string,
	fields ...string,
) {
	t.Helper()
	schema := nestedMap(t, schemas, schemaName)
	requiredValue, ok := schema["required"]
	if !ok {
		t.Fatalf("schema %s has no required fields", schemaName)
	}
	required, ok := requiredValue.([]any)
	if !ok {
		t.Fatalf("schema %s required = %T, want []any", schemaName, requiredValue)
	}
	set := make(map[string]bool, len(required))
	for _, field := range required {
		name, ok := field.(string)
		if !ok {
			t.Fatalf("schema %s has non-string required field %T", schemaName, field)
		}
		set[name] = true
	}
	for _, field := range fields {
		if !set[field] {
			t.Errorf("schema %s does not require %s", schemaName, field)
		}
	}
}

func operationParameter(
	t *testing.T,
	paths map[string]any,
	path string,
	method string,
	name string,
) map[string]any {
	t.Helper()
	operation := nestedMap(t, paths, path, method)
	parameters, ok := operation["parameters"].([]any)
	if !ok {
		t.Fatalf("%s %s parameters = %T, want []any", method, path, operation["parameters"])
	}
	for _, raw := range parameters {
		parameter, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("%s %s parameter = %T, want map[string]any", method, path, raw)
		}
		if parameter["name"] == name {
			return parameter
		}
	}
	t.Fatalf("%s %s has no %s parameter", method, path, name)
	return nil
}

func hasOperationParameter(t *testing.T, operation map[string]any, name string) bool {
	t.Helper()
	parameters, ok := operation["parameters"].([]any)
	if !ok {
		t.Fatalf("operation parameters = %T, want []any", operation["parameters"])
	}
	for _, raw := range parameters {
		parameter, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("operation parameter = %T, want map[string]any", raw)
		}
		if parameter["name"] == name {
			return true
		}
	}
	return false
}

func requireIntegerContract(t *testing.T, schema map[string]any, field string, want int) {
	t.Helper()
	got, ok := schema[field].(int)
	if !ok || got != want {
		t.Fatalf("schema %s = %v (%T), want %d", field, schema[field], schema[field], want)
	}
}

func nestedMap(t *testing.T, root map[string]any, keys ...string) map[string]any {
	t.Helper()
	current := root
	for _, key := range keys {
		value, ok := current[key]
		if !ok {
			t.Fatalf("missing OpenAPI key %s in path %v", key, keys)
		}
		next, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("OpenAPI key %s = %T, want map[string]any", key, value)
		}
		current = next
	}
	return current
}

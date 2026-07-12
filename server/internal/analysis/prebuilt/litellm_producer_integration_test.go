package prebuilt_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis/prebuilt"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	serveringest "github.com/adithyan-ak/agenthound/server/internal/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/projection"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const integrationHashedVirtualKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestLiteLLMProductionLootArtifactIsStrictV2(t *testing.T) {
	fixture := newLiteLLMFixture(t)
	defer fixture.Close()

	data := runAgentHoundLiteLLMLoot(t, fixture.URL)
	assertStrictLiteLLMArtifact(t, &data, fixture.URL)
	fixture.AssertLootRequests(t)
}

func TestIntegrationLiteLLMFingerprintThenLootPreservesGatewayProperties(t *testing.T) {
	ctx, pipeline, db, publicationStore := freshLiteLLMIntegrationHarness(t)
	fixture := newLiteLLMScanFixture(t)
	defer fixture.Close()

	fingerprintData := runAgentHoundLiteLLMScan(t)
	if err := serveringest.NewValidator().Validate(&fingerprintData); err != nil {
		t.Fatalf("strict ingest-v2 validation rejected agenthound scan output: %v", err)
	}
	gatewayID := sdkingest.ComputeNodeID("LiteLLMGateway", fixture.URL)
	fingerprintGateway := findLiteLLMGateway(t, &fingerprintData, gatewayID)
	if fingerprintGateway.PropertySemantics != "" ||
		fingerprintGateway.Properties["endpoint"] != fixture.URL ||
		fingerprintGateway.Properties["auth_method"] != "master_key" ||
		fingerprintGateway.Properties["discovered_via"] != "network_scan" {
		t.Fatalf("scan gateway is not rich and authoritative: %+v", fingerprintGateway)
	}

	first, err := pipeline.Ingest(ctx, &fingerprintData)
	if err != nil {
		t.Fatalf("pipeline ingest of validated fingerprint output: %v", err)
	}
	if first.PublishedRevision == nil ||
		*first.PublishedRevision != 1 ||
		first.Outcome != sdkingest.OutcomeComplete {
		t.Fatalf("fingerprint publication revision 1 failed: %+v", first)
	}

	lootData := runAgentHoundLiteLLMLoot(t, fixture.URL)
	assertStrictLiteLLMArtifact(t, &lootData, fixture.URL)
	lootGateway := findLiteLLMGateway(t, &lootData, gatewayID)
	if lootGateway.ID != fingerprintGateway.ID ||
		strings.Join(lootGateway.Kinds, ",") != strings.Join(fingerprintGateway.Kinds, ",") {
		t.Fatalf(
			"fingerprint/loot gateway identity differs: fingerprint=%+v loot=%+v",
			fingerprintGateway,
			lootGateway,
		)
	}

	second, err := pipeline.Ingest(ctx, &lootData)
	if err != nil {
		t.Fatalf("pipeline ingest of validated loot output: %v", err)
	}
	if second.PublishedRevision == nil ||
		*second.PublishedRevision != 2 ||
		second.Outcome != sdkingest.OutcomeComplete {
		t.Fatalf("loot publication revision 2 failed: %+v", second)
	}

	rows, err := db.Query(
		ctx,
		`MATCH (gateway:LiteLLMGateway {objectid: $gateway_id})
		 RETURN labels(gateway) AS kinds,
		        properties(gateway) AS properties,
		        gateway.observation_tokens AS owners,
		        gateway.observation_reference_tokens AS reference_owners`,
		map[string]any{"gateway_id": gatewayID},
	)
	if err != nil {
		t.Fatalf("query shared LiteLLM gateway: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("shared LiteLLM gateway rows = %+v, want one", rows)
	}
	properties, _ := rows[0]["properties"].(map[string]any)
	if properties["endpoint"] != fixture.URL ||
		properties["auth_method"] != "master_key" ||
		properties["discovered_via"] != "network_scan" ||
		properties["service_kind"] != "litellm" ||
		properties["observation_properties_complete"] != true {
		t.Fatalf("loot replaced or downgraded fingerprint properties: %+v", properties)
	}
	kinds, _ := rows[0]["kinds"].([]any)
	if !containsValue(kinds, "LiteLLMGateway") || !containsValue(kinds, "AIService") {
		t.Fatalf("shared gateway kinds = %v", kinds)
	}
	owners, _ := rows[0]["owners"].([]any)
	referenceOwners, _ := rows[0]["reference_owners"].([]any)
	if len(owners) != 2 || len(referenceOwners) != 1 {
		t.Fatalf("shared gateway owners = %v, reference owners = %v", owners, referenceOwners)
	}

	projection, err := publicationStore.GetProjectionState(ctx)
	if err != nil {
		t.Fatalf("read publication state: %v", err)
	}
	if len(projection.DirtyCoverage) != 0 ||
		projection.PublishedRevision == nil ||
		*projection.PublishedRevision != 2 {
		t.Fatalf("fingerprint-to-loot publication left dirty coverage: %+v", projection)
	}

	queryRows, err := db.Query(ctx, prebuilt.CypherLitellmCredentialLeak, nil)
	if err != nil {
		t.Fatalf("execute guarded LiteLLM prebuilt query: %v", err)
	}
	var produced []map[string]any
	for _, row := range queryRows {
		if row["gateway_id"] == gatewayID {
			produced = append(produced, row)
		}
	}
	assertLiteLLMReferenceRows(t, produced)
	fixture.AssertFingerprintThenLootRequests(t)
}

func TestIntegrationLiteLLMFirstPartyProducerSatisfiesMasterExposureQuery(t *testing.T) {
	rows := runLiteLLMProducerQuery(t, nil)
	assertLiteLLMReferenceRows(t, rows)
}

func TestIntegrationLiteLLMQueryRejectsUnobservedMasterMaterial(t *testing.T) {
	rows := runLiteLLMProducerQuery(t, func(data *sdkingest.IngestData) {
		for i := range data.Graph.Nodes {
			if data.Graph.Nodes[i].Properties["type"] == "master_key" {
				data.Graph.Nodes[i].Properties["material_status"] = "masked"
			}
		}
	})
	if len(rows) != 0 {
		t.Fatalf("masked master material satisfied observed-exposure query: %+v", rows)
	}
}

func runLiteLLMProducerQuery(
	t *testing.T,
	mutate func(*sdkingest.IngestData),
) []map[string]any {
	t.Helper()
	ctx, pipeline, db, publicationStore := freshLiteLLMIntegrationHarness(t)
	fixture := newLiteLLMFixture(t)
	defer fixture.Close()

	data := runAgentHoundLiteLLMLoot(t, fixture.URL)
	if mutate != nil {
		mutate(&data)
	}
	assertStrictLiteLLMArtifact(t, &data, fixture.URL)
	fixture.AssertLootRequests(t)

	gatewayID := sdkingest.ComputeNodeID("LiteLLMGateway", fixture.URL)
	result, err := pipeline.Ingest(ctx, &data)
	if err != nil {
		t.Fatalf("pipeline ingest of validated loot output: %v", err)
	}
	if result.PublishedRevision == nil ||
		result.Outcome != sdkingest.OutcomeComplete {
		t.Fatalf("validated loot output was not published: %+v", result)
	}

	rows, identity, err := projection.GuardedRead(
		ctx,
		publicationStore,
		func() ([]map[string]any, error) {
			return db.Query(ctx, prebuilt.CypherLitellmCredentialLeak, nil)
		},
	)
	if err != nil {
		t.Fatalf("execute guarded LiteLLM prebuilt query: %v", err)
	}
	if identity.ScanID != result.ScanID ||
		identity.Revision != *result.PublishedRevision {
		t.Fatalf(
			"guarded query publication identity = %+v, want scan %q revision %d",
			identity,
			result.ScanID,
			*result.PublishedRevision,
		)
	}
	producedRows := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if row["gateway_id"] == gatewayID {
			producedRows = append(producedRows, row)
		}
	}
	return producedRows
}

func assertLiteLLMReferenceRows(t *testing.T, rows []map[string]any) {
	t.Helper()
	if len(rows) != 2 {
		t.Fatalf("query returned %d rows, want masked apiKey and hashed virtual-key references", len(rows))
	}

	referenceStatuses := map[string]string{}
	for _, row := range rows {
		if row["master_material_status"] != "observed" ||
			row["master_exposure_status"] != "exposed" ||
			row["master_evidence"] != "observed_credential_exposure" {
			t.Fatalf("master evidence was not preserved: %+v", row)
		}
		referenceType, _ := row["reference_type"].(string)
		referenceMaterial, _ := row["reference_material_status"].(string)
		referenceStatuses[referenceType] = referenceMaterial
		if row["reference_exposure_status"] != "not_observed" ||
			row["reference_contains_usable_material"] != false {
			t.Fatalf("reference was presented as usable upstream material: %+v", row)
		}
	}
	if referenceStatuses["apiKey"] != "masked" ||
		referenceStatuses["virtual_key"] != "hashed" {
		t.Fatalf("reference evidence = %v", referenceStatuses)
	}
}

func assertStrictLiteLLMArtifact(
	t *testing.T,
	data *sdkingest.IngestData,
	fixtureURL string,
) {
	t.Helper()
	if err := serveringest.NewValidator().Validate(data); err != nil {
		t.Fatalf("strict ingest-v2 validation rejected agenthound loot output: %v", err)
	}

	gatewayID := sdkingest.ComputeNodeID("LiteLLMGateway", fixtureURL)
	var gateway *sdkingest.Node
	for i := range data.Graph.Nodes {
		if data.Graph.Nodes[i].ID == gatewayID {
			gateway = &data.Graph.Nodes[i]
			break
		}
	}
	if gateway == nil {
		t.Fatalf("production loot envelope omitted gateway %q", gatewayID)
	}
	if len(gateway.Kinds) != 2 ||
		gateway.Kinds[0] != "LiteLLMGateway" ||
		gateway.Kinds[1] != "AIService" ||
		len(gateway.Properties) != 0 ||
		gateway.PropertySemantics != sdkingest.NodePropertySemanticsReferenceOnly {
		t.Fatalf("production loot gateway is not a property-neutral reference: %+v", gateway)
	}
	for _, property := range []string{
		"auth_method",
		"auth_assurance",
		"auth_evidence",
		"discovered_via",
	} {
		if _, exists := gateway.Properties[property]; exists {
			t.Fatalf("loot gateway fabricated fingerprint-owned %q: %+v", property, gateway)
		}
	}
}

func findLiteLLMGateway(
	t *testing.T,
	data *sdkingest.IngestData,
	gatewayID string,
) *sdkingest.Node {
	t.Helper()
	for i := range data.Graph.Nodes {
		if data.Graph.Nodes[i].ID == gatewayID {
			return &data.Graph.Nodes[i]
		}
	}
	t.Fatalf("artifact omitted LiteLLM gateway %q", gatewayID)
	return nil
}

func containsValue(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type liteLLMFixture struct {
	*httptest.Server

	mu                sync.Mutex
	modelInfoRequests int
	keyListRequests   int
	healthRequests    int
}

func newLiteLLMFixture(t *testing.T) *liteLLMFixture {
	t.Helper()
	return newLiteLLMFixtureWithListener(t, nil)
}

func newLiteLLMScanFixture(t *testing.T) *liteLLMFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:4000")
	if err != nil {
		t.Fatalf("bind first-party LiteLLM scan fixture to 127.0.0.1:4000: %v", err)
	}
	return newLiteLLMFixtureWithListener(t, listener)
}

func newLiteLLMFixtureWithListener(
	t *testing.T,
	listener net.Listener,
) *liteLLMFixture {
	t.Helper()
	fixture := &liteLLMFixture{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		switch r.URL.Path {
		case "/model/info":
			fixture.modelInfoRequests++
		case "/key/list":
			fixture.keyListRequests++
		case "/health/liveliness":
			fixture.healthRequests++
		}
		fixture.mu.Unlock()

		if r.URL.Path == "/health/liveliness" {
			_, _ = w.Write([]byte("I'm alive!"))
			return
		}
		if r.Header.Get("Authorization") != "Bearer sk-integration-master-key" {
			http.Error(w, "missing fixture master key", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/model/info":
			_, _ = w.Write([]byte(`{"data":[{
				"model_name":"gpt-4",
				"litellm_params":{
					"model":"openai/gpt-4",
					"api_base":"https://api.openai.com/v1"
				},
				"model_info":{"litellm_provider":"openai"}
			}]}`))
		case "/key/list":
			if r.URL.Query().Get("return_full_object") != "true" ||
				r.URL.Query().Get("size") != "100" ||
				r.URL.Query().Get("page") != "1" {
				http.Error(w, "invalid LiteLLM pagination query", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"keys":["` + integrationHashedVirtualKey + `"],"total_pages":1}`))
		default:
			http.NotFound(w, r)
		}
	})
	if listener == nil {
		fixture.Server = httptest.NewServer(handler)
		return fixture
	}
	fixture.Server = httptest.NewUnstartedServer(handler)
	_ = fixture.Listener.Close()
	fixture.Listener = listener
	fixture.Start()
	return fixture
}

func (f *liteLLMFixture) AssertLootRequests(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.modelInfoRequests != 1 || f.keyListRequests != 1 {
		t.Fatalf(
			"LiteLLM fixture requests: model/info=%d key/list=%d, want one each",
			f.modelInfoRequests,
			f.keyListRequests,
		)
	}
	if f.healthRequests != 0 {
		t.Fatalf("loot required a separate fingerprint probe: health requests=%d", f.healthRequests)
	}
}

func (f *liteLLMFixture) AssertFingerprintThenLootRequests(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.healthRequests != 1 ||
		f.modelInfoRequests != 1 ||
		f.keyListRequests != 1 {
		t.Fatalf(
			"LiteLLM fixture requests: health=%d model/info=%d key/list=%d, want one each",
			f.healthRequests,
			f.modelInfoRequests,
			f.keyListRequests,
		)
	}
}

func runAgentHoundLiteLLMScan(t *testing.T) sdkingest.IngestData {
	t.Helper()
	binaryPath, repositoryRoot := buildAgentHound(t)
	command := exec.Command(
		binaryPath,
		"scan",
		"127.0.0.1",
		"--ports",
		"4000",
		"--scan-output",
		"-",
		"--quiet",
	)
	return runAgentHoundArtifactCommand(t, command, repositoryRoot, "scan")
}

func runAgentHoundLiteLLMLoot(t *testing.T, fixtureURL string) sdkingest.IngestData {
	t.Helper()
	binaryPath, repositoryRoot := buildAgentHound(t)
	command := exec.Command(
		binaryPath,
		"loot",
		strings.TrimPrefix(fixtureURL, "http://"),
		"--type",
		"litellm",
		"--master-key",
		"sk-integration-master-key",
		"--engagement-id",
		"prebuilt-satisfiability",
		"--output",
		"-",
		"--quiet",
	)
	command.Stdin = strings.NewReader("AUTHORIZED\n")
	return runAgentHoundArtifactCommand(t, command, repositoryRoot, "loot")
}

func buildAgentHound(t *testing.T) (string, string) {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration test source path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "..", ".."))
	binaryPath := filepath.Join(t.TempDir(), "agenthound")
	build := exec.Command("go", "build", "-o", binaryPath, "./collector/cmd/agenthound")
	build.Dir = repositoryRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agenthound for production loot regression: %v\n%s", err, output)
	}
	return binaryPath, repositoryRoot
}

func runAgentHoundArtifactCommand(
	t *testing.T,
	command *exec.Cmd,
	repositoryRoot string,
	verb string,
) sdkingest.IngestData {
	t.Helper()
	command.Dir = repositoryRoot
	command.Env = integrationCommandEnv(t.TempDir())
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("agenthound %s failed: %v\nstderr:\n%s", verb, err, stderr.String())
	}

	var data sdkingest.IngestData
	if err := sdkingest.DecodeStrict(bytes.NewReader(stdout.Bytes()), &data); err != nil {
		t.Fatalf(
			"strict JSON decode rejected agenthound %s output: %v\nstdout:\n%s\nstderr:\n%s",
			verb,
			err,
			stdout.String(),
			stderr.String(),
		)
	}
	return data
}

func integrationCommandEnv(home string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "HOME=") ||
			strings.HasPrefix(entry, "AGENTHOUND_QUIET=") {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "HOME="+home, "AGENTHOUND_QUIET=1")
}

func freshLiteLLMIntegrationHarness(
	t *testing.T,
) (context.Context, *serveringest.Pipeline, *graph.DB, *appdb.FindingStore) {
	t.Helper()
	if os.Getenv("AGENTHOUND_FRESH_DB_INTEGRATION") != "1" {
		t.Skip("set AGENTHOUND_FRESH_DB_INTEGRATION=1 for destructive fresh-database integration")
	}
	neo4jURI := os.Getenv("AGENTHOUND_NEO4J_URI")
	pgURI := os.Getenv("AGENTHOUND_PG_URI")
	if neo4jURI == "" || pgURI == "" {
		t.Skip("AGENTHOUND_NEO4J_URI and AGENTHOUND_PG_URI are required")
	}

	ctx := context.Background()
	driver, err := graph.NewDriver(
		neo4jURI,
		os.Getenv("AGENTHOUND_NEO4J_USER"),
		os.Getenv("AGENTHOUND_NEO4J_PASSWORD"),
	)
	if err != nil {
		t.Fatalf("connect Neo4j: %v", err)
	}
	t.Cleanup(func() { _ = driver.Close(ctx) })
	writer := graph.NewWriter(driver)
	db := graph.NewDB(graph.NewReader(driver), writer)
	if _, err := db.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil); err != nil {
		t.Fatalf("reset Neo4j: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil); err != nil {
			t.Errorf("clean Neo4j integration data: %v", err)
		}
	})
	if err := graph.InitSchema(ctx, driver); err != nil {
		t.Fatalf("initialize Neo4j schema: %v", err)
	}

	admin, err := appdb.NewPool(pgURI)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	schema := fmt.Sprintf("agenthound_litellm_test_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		admin.Close()
		t.Fatalf("create isolated PostgreSQL schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(pgURI)
	if err != nil {
		admin.Close()
		t.Fatalf("parse PostgreSQL config: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatalf("connect isolated PostgreSQL schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop isolated PostgreSQL schema: %v", err)
		}
		admin.Close()
	})
	if err := appdb.RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate PostgreSQL: %v", err)
	}

	scanStore := appdb.NewScanStore(pool)
	findingStore := appdb.NewFindingStore(pool)
	return ctx, serveringest.NewPipeline(
		writer,
		db,
		scanStore,
		findingStore,
	), db, findingStore
}

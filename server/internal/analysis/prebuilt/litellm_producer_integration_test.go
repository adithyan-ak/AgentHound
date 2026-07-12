package prebuilt_test

import (
	"bytes"
	"context"
	"fmt"
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

func TestIntegrationLiteLLMFirstPartyProducerSatisfiesMasterExposureQuery(t *testing.T) {
	rows := runLiteLLMProducerQuery(t, nil)
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
	ctx, pipeline, db := freshLiteLLMIntegrationHarness(t)
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

	rows, err := db.Query(ctx, prebuilt.CypherLitellmCredentialLeak, nil)
	if err != nil {
		t.Fatalf("execute LiteLLM prebuilt query: %v", err)
	}
	producedRows := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if row["gateway_id"] == gatewayID {
			producedRows = append(producedRows, row)
		}
	}
	return producedRows
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
		gateway.Properties["endpoint"] != fixtureURL {
		t.Fatalf("production loot gateway is not canonical: %+v", gateway)
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

type liteLLMFixture struct {
	*httptest.Server

	mu                sync.Mutex
	modelInfoRequests int
	keyListRequests   int
	healthRequests    int
}

func newLiteLLMFixture(t *testing.T) *liteLLMFixture {
	t.Helper()
	fixture := &liteLLMFixture{}
	fixture.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
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

func runAgentHoundLiteLLMLoot(t *testing.T, fixtureURL string) sdkingest.IngestData {
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
	command.Dir = repositoryRoot
	command.Env = integrationCommandEnv(t.TempDir())
	command.Stdin = strings.NewReader("AUTHORIZED\n")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("agenthound loot failed: %v\nstderr:\n%s", err, stderr.String())
	}

	var data sdkingest.IngestData
	if err := sdkingest.DecodeStrict(bytes.NewReader(stdout.Bytes()), &data); err != nil {
		t.Fatalf(
			"strict JSON decode rejected agenthound loot output: %v\nstdout:\n%s\nstderr:\n%s",
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
) (context.Context, *serveringest.Pipeline, *graph.DB) {
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

	return ctx, serveringest.NewPipeline(
		writer,
		db,
		appdb.NewScanStore(pool),
		appdb.NewFindingStore(pool),
	), db
}

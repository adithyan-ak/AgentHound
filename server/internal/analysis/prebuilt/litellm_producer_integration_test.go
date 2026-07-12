package prebuilt_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/modules/litellmfp"
	"github.com/adithyan-ak/agenthound/modules/litellmloot"
	"github.com/adithyan-ak/agenthound/sdk/action"
	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis/prebuilt"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	serveringest "github.com/adithyan-ak/agenthound/server/internal/ingest"
)

const integrationHashedVirtualKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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
	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	if uri == "" {
		t.Skip("skipping integration test: AGENTHOUND_NEO4J_URI not set")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health/liveliness":
			_, _ = w.Write([]byte("I'm alive!"))
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
			_, _ = w.Write([]byte(`{"keys":["` + integrationHashedVirtualKey + `"],"total_pages":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	target := action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(server.URL, "http://"),
	}
	fingerprinter, err := litellmfp.New()
	if err != nil {
		t.Fatalf("create LiteLLM fingerprinter: %v", err)
	}
	fingerprint, err := fingerprinter.Fingerprint(context.Background(), target)
	if err != nil {
		t.Fatalf("fingerprint LiteLLM: %v", err)
	}
	if !fingerprint.Matched || fingerprint.IngestData == nil {
		t.Fatal("first-party LiteLLM fingerprinter did not emit a gateway")
	}

	loot, err := (&litellmloot.Looter{}).Loot(
		context.Background(),
		target,
		action.LootOptions{
			Credentials:  map[string]string{"master_key": "sk-integration-master-key"},
			EngagementID: "prebuilt-satisfiability",
		},
	)
	if err != nil {
		t.Fatalf("loot LiteLLM: %v", err)
	}
	if loot.IngestData == nil {
		t.Fatal("first-party LiteLLM looter emitted no graph data")
	}

	data := &sdkingest.IngestData{Graph: fingerprint.IngestData.Graph}
	data.Graph.Nodes = append(data.Graph.Nodes, loot.IngestData.Graph.Nodes...)
	data.Graph.Edges = append(data.Graph.Edges, loot.IngestData.Graph.Edges...)
	sdkingest.TagObservationDomain(&data.Graph, "prebuilt-litellm-integration")
	if mutate != nil {
		mutate(data)
	}
	serveringest.NewNormalizer().Normalize(data)

	ctx := context.Background()
	driver, err := graph.NewDriver(
		uri,
		os.Getenv("AGENTHOUND_NEO4J_USER"),
		os.Getenv("AGENTHOUND_NEO4J_PASSWORD"),
	)
	if err != nil {
		t.Fatalf("connect to Neo4j: %v", err)
	}
	defer driver.Close(ctx)
	if err := graph.InitSchema(ctx, driver); err != nil {
		t.Fatalf("initialize Neo4j schema: %v", err)
	}

	scanID := "prebuilt-litellm-" + strings.TrimPrefix(server.URL, "http://")
	writer := graph.NewWriter(driver)
	db := graph.NewDB(graph.NewReader(driver), writer)
	cleanup := func() {
		_, _ = db.ExecuteWrite(
			ctx,
			"MATCH (n) WHERE n.scan_id = $scan_id DETACH DELETE n",
			map[string]any{"scan_id": scanID},
		)
	}
	cleanup()
	defer cleanup()

	if _, err := writer.WriteNodes(ctx, data.Graph.Nodes, scanID); err != nil {
		t.Fatalf("write producer nodes: %v", err)
	}
	if _, err := writer.WriteEdges(ctx, data.Graph.Edges, scanID); err != nil {
		t.Fatalf("write producer edges: %v", err)
	}
	rows, err := db.Query(ctx, prebuilt.CypherLitellmCredentialLeak, nil)
	if err != nil {
		t.Fatalf("execute LiteLLM prebuilt query: %v", err)
	}
	gatewayID := fingerprint.IngestData.Graph.Nodes[0].ID
	producedRows := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if row["gateway_id"] == gatewayID {
			producedRows = append(producedRows, row)
		}
	}
	return producedRows
}

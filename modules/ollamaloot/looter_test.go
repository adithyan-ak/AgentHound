package ollamaloot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

const tagsBody = `{
	"models":[
		{"name":"llama3:latest","model":"llama3:latest","digest":"sha256:abcdef0123456789","size":4661211808,"modified_at":"2026-04-01T12:00:00Z"},
		{"name":"support-agent-v3:latest","model":"support-agent-v3:latest","digest":"sha256:fedcba9876543210","size":4700000000,"modified_at":"2026-04-15T09:00:00Z"}
	]
}`

const modelfileLlama = "FROM llama3\n"
const modelfileFinetune = "FROM llama3\nSYSTEM \"\"\"You are SupportBot for Acme Corp.\"\"\"\n"

func ollamaStubServer(t *testing.T, opts stubOpts) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(tagsBody))
		case "/api/show":
			defer func() { _ = r.Body.Close() }()
			body, _ := readAllString(r)
			if strings.Contains(body, "support-agent") {
				_, _ = w.Write([]byte(`{"modelfile":` + jsonString(modelfileFinetune) + `,"template":"{{ .System }}","system":"You are SupportBot for Acme Corp.","details":{"family":"llama","parameter_size":"8B","quantization_level":"Q4_0"}}`))
			} else {
				_, _ = w.Write([]byte(`{"modelfile":` + jsonString(modelfileLlama) + `,"template":"{{ .Prompt }}","details":{"family":"llama","parameter_size":"8B","quantization_level":"Q4_0"}}`))
			}
		case "/api/embeddings":
			if !opts.allowEmbeddings {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write([]byte(`{"embedding":[0.1,0.2,0.3]}`))
		default:
			w.WriteHeader(404)
		}
	}))
}

type stubOpts struct {
	allowEmbeddings bool
}

func TestLoot_AnonymousHappyPath(t *testing.T) {
	srv := ollamaStubServer(t, stubOpts{})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	if res.IngestData == nil {
		t.Fatal("IngestData nil")
	}
	// 1 OllamaInstance + 2 AIModel = 3 nodes; 2 PROVIDES_MODEL edges.
	if len(res.IngestData.Graph.Nodes) != 3 {
		t.Errorf("nodes: got %d, want 3", len(res.IngestData.Graph.Nodes))
	}
	if len(res.IngestData.Graph.Edges) != 2 {
		t.Errorf("edges: got %d, want 2", len(res.IngestData.Graph.Edges))
	}

	var ollama, modelLlama, modelFinetune int
	for _, n := range res.IngestData.Graph.Nodes {
		switch n.Kinds[0] {
		case "OllamaInstance":
			ollama++
		case "AIModel":
			if name, _ := n.Properties["name"].(string); strings.Contains(name, "support-agent") {
				modelFinetune++
				if got, _ := n.Properties["is_finetune"].(bool); !got {
					t.Errorf("support-agent should be flagged is_finetune=true")
				}
				if vh, _ := n.Properties["value_hash"].(string); vh == "" {
					t.Errorf("AIModel.value_hash should be populated for fine-tune")
				}
				if got, _ := n.Properties["has_system_prompt"].(bool); !got {
					t.Errorf("support-agent should be flagged has_system_prompt=true")
				}
				if _, ok := n.Properties["modelfile"]; ok {
					t.Errorf("modelfile should NOT be on node when IncludeCredentialValues=false")
				}
			} else {
				modelLlama++
			}
		}
	}
	if ollama != 1 || modelLlama != 1 || modelFinetune != 1 {
		t.Errorf("expected 1 OllamaInstance + 1 plain + 1 fine-tune; got %d/%d/%d",
			ollama, modelLlama, modelFinetune)
	}

	for _, e := range res.IngestData.Graph.Edges {
		if e.Kind != "PROVIDES_MODEL" {
			t.Errorf("edge kind = %q, want PROVIDES_MODEL", e.Kind)
		}
		if e.SourceKind != "OllamaInstance" || e.TargetKind != "AIModel" {
			t.Errorf("edge endpoints = %s -> %s, want OllamaInstance -> AIModel", e.SourceKind, e.TargetKind)
		}
	}
}

func TestLoot_IncludeCredentialValuesEmitsModelfile(t *testing.T) {
	srv := ollamaStubServer(t, stubOpts{})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{IncludeCredentialValues: true})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	var saw bool
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Kinds[0] != "AIModel" {
			continue
		}
		if mf, _ := n.Properties["modelfile"].(string); strings.Contains(mf, "SupportBot") {
			saw = true
			if sp, _ := n.Properties["system_prompt"].(string); sp == "" {
				t.Errorf("system_prompt should be populated when IncludeCredentialValues=true")
			}
		}
	}
	if !saw {
		t.Error("modelfile not surfaced on any AIModel node when IncludeCredentialValues=true")
	}
}

func TestLoot_IncludeEmbeddingsProbesPOST(t *testing.T) {
	srv := ollamaStubServer(t, stubOpts{allowEmbeddings: true})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{
		Extras: map[string]any{"include-embeddings": true},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	confirmed, _ := res.IngestData.Graph.Nodes[0].Properties["embedding_capability_confirmed"].(bool)
	if !confirmed {
		t.Error("embedding_capability_confirmed should be true after successful probe")
	}
}

func TestLoot_NoModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			_, _ = w.Write([]byte(`{"models":[]}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	// 1 OllamaInstance, 0 AIModels.
	if got := len(res.IngestData.Graph.Nodes); got != 1 {
		t.Errorf("nodes: got %d, want 1 (OllamaInstance only)", got)
	}
	if got := len(res.IngestData.Graph.Edges); got != 0 {
		t.Errorf("edges: got %d, want 0", got)
	}
}

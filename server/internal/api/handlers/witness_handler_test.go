package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func canReachFingerprint(sourceID, targetID string) string {
	sum := sha256.Sum256([]byte("CAN_REACH|" + sourceID + "|" + targetID))
	return hex.EncodeToString(sum[:])[:16]
}

func TestHandleWitness_Success(t *testing.T) {
	serverID := "sha256:wsrv"
	uri := "postgres://prod/db"
	resID := ingest.ComputeNodeID("MCPResource", serverID, uri)
	agentID := "sha256:wagent"
	credID := "sha256:wcred"
	findingID := canReachFingerprint(agentID, resID)

	mock := &graph.MockGraphDB{QueryResult: []map[string]any{{
		"agent_id":              agentID,
		"resource_id":           resID,
		"resource_uri":          uri,
		"credential_id":         credID,
		"credential_value_hash": "abcd1234",
		"credential_merge_key":  "value_hash",
		"server_id":             serverID,
	}}}
	h := newStableAnalysisHandler(mock) // published revision 1

	w := httptest.NewRecorder()
	r := withChiURLParam(
		newTestRequest(http.MethodGet, "/api/v1/analysis/findings/"+findingID+"/witness", nil),
		"id", findingID,
	)
	h.HandleWitness(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Witness map[string]any `json:"witness"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Witness["credential_id"] != credID || resp.Witness["server_id"] != serverID {
		t.Fatalf("witness identity wrong: %+v", resp.Witness)
	}
	// Publication revision must be stamped from the guarded projection read (1).
	if rev, _ := resp.Witness["publication_revision"].(float64); rev != 1 {
		t.Fatalf("publication_revision = %v, want 1", resp.Witness["publication_revision"])
	}
	// Sanitizer: the credential value_hash is echoed, but no raw value field.
	if resp.Witness["credential_value_hash"] != "abcd1234" {
		t.Fatalf("value_hash echo missing: %+v", resp.Witness)
	}
	if _, leaked := resp.Witness["value"]; leaked {
		t.Fatal("witness must never carry a raw credential value")
	}
}

func TestHandleWitness_NotFound(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: []map[string]any{}}
	h := newStableAnalysisHandler(mock)
	findingID := "aabbccdd11223344"

	w := httptest.NewRecorder()
	r := withChiURLParam(
		newTestRequest(http.MethodGet, "/api/v1/analysis/findings/"+findingID+"/witness", nil),
		"id", findingID,
	)
	h.HandleWitness(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

func TestHandleWitness_InvalidID(t *testing.T) {
	h := newStableAnalysisHandler(&graph.MockGraphDB{})
	w := httptest.NewRecorder()
	r := withChiURLParam(
		newTestRequest(http.MethodGet, "/api/v1/analysis/findings/not-hex/witness", nil),
		"id", "not-hex",
	)
	h.HandleWitness(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

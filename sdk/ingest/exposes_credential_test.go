package ingest

import "testing"

// TestExposesCredentialEdge locks the EXPOSES_CREDENTIAL contract shared by
// every service collector that emits exposed upstream secrets (litellmcollect,
// openwebuicollect, ...). A typo in Kind or a swap of confidence/risk_weight
// here would silently propagate to all of them, so the constants are
// asserted explicitly rather than via an integration test.
func TestExposesCredentialEdge(t *testing.T) {
	e := ExposesCredentialEdge("svc-1", "cred-1", "litellm_keys", "/key/info")

	if e.Source != "svc-1" {
		t.Errorf("Source: got %q, want %q", e.Source, "svc-1")
	}
	if e.Target != "cred-1" {
		t.Errorf("Target: got %q, want %q", e.Target, "cred-1")
	}
	if e.Kind != "EXPOSES_CREDENTIAL" {
		t.Errorf("Kind: got %q, want %q", e.Kind, "EXPOSES_CREDENTIAL")
	}
	if e.SourceKind != "AIService" {
		t.Errorf("SourceKind: got %q, want %q", e.SourceKind, "AIService")
	}
	if e.TargetKind != "Credential" {
		t.Errorf("TargetKind: got %q, want %q", e.TargetKind, "Credential")
	}

	if e.Properties["confidence"] != 1.0 {
		t.Errorf("confidence: got %v, want 1.0", e.Properties["confidence"])
	}
	if e.Properties["risk_weight"] != 0.1 {
		t.Errorf("risk_weight: got %v, want 0.1", e.Properties["risk_weight"])
	}

	ev, ok := e.Properties["evidence"].(map[string]any)
	if !ok {
		t.Fatalf("evidence: got %T, want map[string]any", e.Properties["evidence"])
	}
	if ev["endpoint"] != "/key/info" {
		t.Errorf("evidence.endpoint: got %v, want %q", ev["endpoint"], "/key/info")
	}
	if ev["source"] != "litellm_keys" {
		t.Errorf("evidence.source: got %v, want %q", ev["source"], "litellm_keys")
	}
	if _, present := ev["engagement_id"]; present {
		t.Errorf("removed engagement_id is still present: %v", ev)
	}
}

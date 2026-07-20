package riskscore

import (
	"context"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestIntegrationEffectiveAuthRiskExactness(t *testing.T) {
	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	if uri == "" {
		t.Skip("skipping integration test: AGENTHOUND_NEO4J_URI not set")
	}
	ctx := context.Background()
	driver, err := graph.NewDriver(
		uri,
		os.Getenv("AGENTHOUND_NEO4J_USER"),
		os.Getenv("AGENTHOUND_NEO4J_PASSWORD"),
	)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)
	db := graph.NewDB(graph.NewReader(driver), graph.NewWriter(driver))

	const scanID = "test-effective-auth-risk"
	cleanup := func() {
		_, _ = db.ExecuteWrite(ctx,
			"MATCH (n {scan_id: $scan_id}) DETACH DELETE n",
			map[string]any{"scan_id": scanID})
	}
	cleanup()
	defer cleanup()

	_, err = db.ExecuteWrite(ctx, `CREATE
  (agent:AgentInstance {
    objectid: 'risk-effective-agent', name: 'Effective Agent', scan_id: $scan_id
  }),
  (server:MCPServer {
    objectid: 'risk-effective-server', name: 'Effective Server', scan_id: $scan_id,
    auth_method: 'bearer', auth_assurance: 'moderate', auth_evidence: 'configured_credential',
    effective_auth_method: 'none', effective_auth_assurance: 'unauthenticated',
    effective_auth_evidence: 'anonymous_probe_succeeded', effective_auth_source: 'observed'
  }),
  (host:Host {
    objectid: 'risk-effective-host', hostname: 'localhost', scope: 'local', scan_id: $scan_id
  }),
  (a2a:A2AAgent {
    objectid: 'risk-effective-a2a', name: 'Effective A2A', scan_id: $scan_id,
    auth_method: 'mtls', auth_assurance: 'strong', auth_evidence: 'declared_security_scheme',
    effective_auth_method: 'mtls', effective_auth_assurance: 'strong',
    effective_auth_evidence: 'declared_security_scheme', effective_auth_source: 'configured'
  }),
  (a2a_observed:A2AAgent {
    objectid: 'risk-effective-a2a-observed', name: 'Observed Anonymous A2A', scan_id: $scan_id,
    auth_method: 'unknown', auth_assurance: 'unknown', auth_evidence: 'declared_security_scheme',
    effective_auth_method: 'none', effective_auth_assurance: 'unauthenticated',
    effective_auth_evidence: 'anonymous_probe_succeeded', effective_auth_source: 'observed'
  }),
  (a2a_raw:A2AAgent {
    objectid: 'risk-effective-a2a-raw', name: 'Raw Anonymous A2A', scan_id: $scan_id,
    auth_method: 'none', auth_assurance: 'unauthenticated', auth_evidence: 'anonymous_probe_succeeded',
    effective_auth_method: 'none', effective_auth_assurance: 'unknown',
    effective_auth_evidence: 'anonymous_probe_succeeded', effective_auth_source: 'configured'
  }),
  (agent)-[:TRUSTS_SERVER {
    risk_weight: 0.5, auth_assessment_complete: true,
    effective_risk_weight: 0.1, effective_auth_assessment_complete: true,
    effective_auth_source: 'observed'
  }]->(server),
  (server)-[:RUNS_ON {risk_weight: 0.1}]->(host)
RETURN 1 AS created`, map[string]any{"scan_id": scanID})
	if err != nil {
		t.Fatalf("seed effective risk graph: %v", err)
	}

	agentAssessment, err := AgentRiskAssessment(ctx, db, "risk-effective-agent")
	if err != nil {
		t.Fatalf("agent risk: %v", err)
	}
	if !agentAssessment.Complete || agentAssessment.Score != 18 ||
		agentAssessment.Min != 18 || agentAssessment.Max != 18 {
		t.Fatalf("agent effective auth risk = %+v, want exact 18", agentAssessment)
	}

	serverAssessment, err := ServerRiskAssessment(ctx, db, "risk-effective-server")
	if err != nil {
		t.Fatalf("server risk: %v", err)
	}
	// auth=100 * 0.35, local exposure=20 * 0.20, other factors=0.
	if !serverAssessment.Complete || serverAssessment.Score != 39 ||
		serverAssessment.Min != 39 || serverAssessment.Max != 39 {
		t.Fatalf("server effective auth risk = %+v, want exact 39", serverAssessment)
	}

	a2aAssessment, err := A2AAgentRiskAssessment(ctx, db, "risk-effective-a2a")
	if err != nil {
		t.Fatalf("A2A risk: %v", err)
	}
	// Configured-derived mTLS auth remains 10 * 0.30 when no exact A2A probe wins.
	if !a2aAssessment.Complete || a2aAssessment.Score != 3 ||
		a2aAssessment.Min != 3 || a2aAssessment.Max != 3 {
		t.Fatalf("A2A effective configured auth risk = %+v, want exact 3", a2aAssessment)
	}

	observedA2A, err := A2AAgentRiskAssessment(ctx, db, "risk-effective-a2a-observed")
	if err != nil {
		t.Fatalf("observed A2A risk: %v", err)
	}
	if !observedA2A.Complete || observedA2A.Score != 30 ||
		observedA2A.Min != 30 || observedA2A.Max != 30 {
		t.Fatalf("A2A effective observed auth risk = %+v, want exact 30", observedA2A)
	}

	rawA2A, err := A2AAgentRiskAssessment(ctx, db, "risk-effective-a2a-raw")
	if err != nil {
		t.Fatalf("raw A2A risk: %v", err)
	}
	if rawA2A.Complete || rawA2A.Min != 0 || rawA2A.Max != 30 ||
		len(rawA2A.UnknownFactors) != 1 || rawA2A.UnknownFactors[0] != "auth_source" {
		t.Fatalf("raw configured anonymous A2A risk = %+v, want auth-source bound 0-30", rawA2A)
	}
}

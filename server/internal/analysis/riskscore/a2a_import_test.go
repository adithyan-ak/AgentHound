package riskscore_test

import (
	"context"
	"strings"
	"testing"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis/riskscore"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	serveringest "github.com/adithyan-ak/agenthound/server/internal/ingest"
)

func TestStrictV4ImportedA2ANoneAuthRequiresProbeEvidence(t *testing.T) {
	for _, test := range []struct {
		name          string
		authEvidence  string
		observed      bool
		wantComplete  bool
		wantMin       float64
		wantMax       float64
		wantUnknownBy string
	}{
		{
			name:          "declared none without probe is bounded unknown",
			authEvidence:  "unknown",
			wantMax:       30,
			wantUnknownBy: "auth_evidence",
		},
		{
			name:          "legacy raw anonymous evidence lacks runtime provenance",
			authEvidence:  "anonymous_probe_succeeded",
			wantMax:       30,
			wantUnknownBy: "auth_source",
		},
		{
			name:         "successful bounded anonymous probe is exact",
			authEvidence: "declared_security_scheme",
			observed:     true,
			wantComplete: true,
			wantMin:      30,
			wantMax:      30,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := strictV4A2AImport(test.authEvidence, test.observed)
			if err := serveringest.NewValidator().Validate(data); err != nil {
				t.Fatalf("strict-v3 A2A import rejected: %v", err)
			}

			properties := data.Graph.Nodes[0].Properties
			effectiveEvidence := properties["auth_evidence"]
			effectiveAssurance := "unknown"
			effectiveSource := "configured"
			if test.observed {
				effectiveEvidence = properties["observed_auth_evidence"]
				effectiveAssurance = "unauthenticated"
				effectiveSource = "observed"
			}
			db := &graph.MockGraphDB{
				QueryFunc: func(
					_ context.Context,
					cypher string,
					_ map[string]any,
				) ([]map[string]any, error) {
					if strings.Contains(cypher, "auth_method") {
						return []map[string]any{{
							"am":             properties["auth_method"],
							"auth_assurance": effectiveAssurance,
							"auth_evidence":  effectiveEvidence,
							"auth_source":    effectiveSource,
						}}, nil
					}
					return nil, nil
				},
			}
			assessment, err := riskscore.A2AAgentRiskAssessment(
				context.Background(),
				db,
				data.Graph.Nodes[0].ID,
			)
			if err != nil {
				t.Fatal(err)
			}
			if assessment.Complete != test.wantComplete ||
				assessment.Min != test.wantMin ||
				assessment.Max != test.wantMax ||
				assessment.Score != test.wantMax {
				t.Fatalf("assessment = %+v", assessment)
			}
			if test.wantUnknownBy == "" {
				if len(assessment.UnknownFactors) != 0 {
					t.Fatalf("exact assessment has unknowns: %+v", assessment)
				}
			} else if len(assessment.UnknownFactors) != 1 ||
				assessment.UnknownFactors[0] != test.wantUnknownBy {
				t.Fatalf("unknown factors = %v", assessment.UnknownFactors)
			}
		})
	}
}

func strictV4A2AImport(authEvidence string, observed bool) *sdkingest.IngestData {
	scope := sdkingest.CanonicalCoverageKey(
		"a2a",
		"target",
		"https://imported.example/a2a",
	)
	data := &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Version: sdkingest.CurrentVersion,
			Type:    sdkingest.IngestType,
			Identity: sdkingest.NewCollectionIdentity(
				[]sdkingest.IdentityEvidence{
					{Kind: "os_instance", Digest: "hmac-sha256:" + strings.Repeat("a", 64)},
					{Kind: "principal", Digest: "hmac-sha256:" + strings.Repeat("b", 64)},
				},
				[]sdkingest.IdentityEvidence{{Kind: "network_profile", Digest: "hmac-sha256:" + strings.Repeat("c", 64)}},
				sdkingest.NetworkClassPrivate,
			),
			Collector:        "a2a",
			CollectorVersion: "import-test",
			Timestamp:        "2026-07-12T00:00:00Z",
			ScanID:           "strict-v4-a2a-import",
			Collection: &sdkingest.CollectionReport{
				State:        sdkingest.OutcomeComplete,
				CoverageKeys: []string{scope},
				Outcomes: []sdkingest.CollectionOutcome{{
					Collector:   "a2a",
					CoverageKey: scope,
					Target:      "https://imported.example/a2a",
					Method:      "agent_card",
					State:       sdkingest.OutcomeComplete,
					Items:       1,
				}},
			},
			Ruleset: sdkingest.EmptyRulesetManifest(),
			IdentitySchemes: []sdkingest.IdentityScheme{{
				EntityKind: "A2AAgent",
				Scheme:     "url_v1",
				Version:    1,
			}},
		},
		Graph: sdkingest.GraphData{
			Nodes: []sdkingest.Node{{
				ID:                 "imported-a2a",
				Kinds:              []string{"A2AAgent"},
				ObservationDomains: []string{scope},
				Properties: map[string]any{
					"name":                          "Imported Agent",
					"auth_method":                   "none",
					"auth_assurance":                "unauthenticated",
					"auth_evidence":                 authEvidence,
					"signature_verification_status": "unknown",
					"signature_key_source":          "none",
					"signature_key_trust":           "unknown",
				},
			}},
			Edges: []sdkingest.Edge{},
		},
	}
	if observed {
		properties := data.Graph.Nodes[0].Properties
		properties["observed_auth_method"] = "none"
		properties["observed_auth_assurance"] = "unauthenticated"
		properties["observed_auth_evidence"] = "anonymous_probe_succeeded"
		properties["auth_probe_method"] = "get_task_nonexistent"
		properties["auth_probe_status"] = "anonymous_protocol_access"
		properties["auth_probe_detail"] = "task_not_found_v1"
	}
	return data
}

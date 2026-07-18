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

func TestStrictV2ImportedA2ANoneAuthRequiresProbeEvidence(t *testing.T) {
	for _, test := range []struct {
		name          string
		authEvidence  string
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
			name:         "successful anonymous probe is exact",
			authEvidence: "anonymous_probe_succeeded",
			wantComplete: true,
			wantMin:      30,
			wantMax:      30,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := strictV2A2AImport(test.authEvidence)
			if err := serveringest.NewValidator().Validate(data); err != nil {
				t.Fatalf("strict-v2 A2A import rejected: %v", err)
			}

			properties := data.Graph.Nodes[0].Properties
			db := &graph.MockGraphDB{
				QueryFunc: func(
					_ context.Context,
					cypher string,
					_ map[string]any,
				) ([]map[string]any, error) {
					if strings.Contains(cypher, "auth_method") {
						return []map[string]any{{
							"am":            properties["auth_method"],
							"auth_evidence": properties["auth_evidence"],
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

func strictV2A2AImport(authEvidence string) *sdkingest.IngestData {
	scope := sdkingest.CanonicalCoverageKey(
		"a2a",
		"target",
		"https://imported.example/a2a",
	)
	return &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Version:          sdkingest.CurrentVersion,
			Type:             sdkingest.IngestType,
			Collector:        "a2a",
			CollectorVersion: "import-test",
			Timestamp:        "2026-07-12T00:00:00Z",
			ScanID:           "strict-v2-a2a-import",
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
}

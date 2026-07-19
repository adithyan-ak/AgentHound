package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

type FindingDetail struct {
	Finding     model.Finding     `json:"finding"`
	AttackPath  *AttackPath       `json:"attack_path"`
	Remediation []RemediationStep `json:"remediation"`
	Impact      *Impact           `json:"impact"`
	Snapshot    *FindingSnapshot  `json:"snapshot"`
}

type FindingSnapshot struct {
	Scope            string                     `json:"scope"`
	ScanID           string                     `json:"scan_id"`
	Revision         *int64                     `json:"revision"`
	PublishedAt      *time.Time                 `json:"published_at"`
	ProjectionStatus string                     `json:"projection_status"`
	SnapshotStatus   string                     `json:"snapshot_status"`
	Available        bool                       `json:"available"`
	Stale            bool                       `json:"stale"`
	EvidenceState    FindingDetailEvidenceState `json:"evidence_state"`
}

type FindingDetailEvidenceState string

const (
	FindingDetailEvidenceUnavailable    FindingDetailEvidenceState = "unavailable"
	FindingDetailEvidencePersistedExact FindingDetailEvidenceState = "persisted_exact_evidence"
)

type AttackPath struct {
	Nodes           []PathNode             `json:"nodes"`
	Edges           []PathEdge             `json:"edges"`
	Shape           EvidenceShape          `json:"shape"`
	Continuity      EvidenceContinuity     `json:"continuity"`
	Direction       EvidenceDirection      `json:"direction"`
	Completeness    EvidenceCompleteness   `json:"completeness"`
	Linearization   *EvidenceLinearization `json:"linearization,omitempty"`
	Cost            AttackCost             `json:"cost"`
	TotalRiskWeight *float64               `json:"total_risk_weight"`
}

type EvidenceShape string

const (
	EvidenceShapeLinear       EvidenceShape = "linear"
	EvidenceShapeBranched     EvidenceShape = "branched"
	EvidenceShapeDisconnected EvidenceShape = "disconnected"
	EvidenceShapeCyclic       EvidenceShape = "cyclic"
	EvidenceShapeNodesOnly    EvidenceShape = "nodes_only"
)

type EvidenceDirection string

const (
	EvidenceDirectionForward       EvidenceDirection = "forward"
	EvidenceDirectionReverse       EvidenceDirection = "reverse"
	EvidenceDirectionMixed         EvidenceDirection = "mixed"
	EvidenceDirectionNonLinear     EvidenceDirection = "non_linear"
	EvidenceDirectionNotApplicable EvidenceDirection = "not_applicable"
)

type EvidenceState string

const (
	EvidenceStateComplete      EvidenceState = "complete"
	EvidenceStateIncomplete    EvidenceState = "incomplete"
	EvidenceStateNotApplicable EvidenceState = "not_applicable"
)

type EvidenceContinuityState string

const (
	EvidenceContinuityContinuous    EvidenceContinuityState = "continuous"
	EvidenceContinuityDiscontinuous EvidenceContinuityState = "discontinuous"
	EvidenceContinuityNotApplicable EvidenceContinuityState = "not_applicable"
)

type EvidenceContinuity struct {
	State          EvidenceContinuityState `json:"state"`
	ComponentCount int                     `json:"component_count"`
	MissingNodeIDs []string                `json:"missing_node_ids"`
}

type EvidenceCompleteness struct {
	State   EvidenceState `json:"state"`
	Reasons []string      `json:"reasons"`
}

type EvidenceLinearization struct {
	NodeIDs     []string `json:"node_ids"`
	EdgeIndexes []int    `json:"edge_indexes"`
}

type AttackCost struct {
	State                    EvidenceState `json:"state"`
	Value                    *float64      `json:"value"`
	Reasons                  []string      `json:"reasons"`
	MissingWeightEdgeIndexes []int         `json:"missing_weight_edge_indexes"`
}

type PathNode struct {
	ID         string         `json:"id"`
	Kinds      []string       `json:"kinds"`
	Properties map[string]any `json:"properties"`
}

type PathEdge struct {
	Source     string          `json:"source"`
	Target     string          `json:"target"`
	Kind       string          `json:"kind"`
	Properties map[string]any  `json:"properties"`
	Synthetic  bool            `json:"synthetic"`
	Provenance *EdgeProvenance `json:"provenance,omitempty"`
}

type EdgeProvenance struct {
	Type            string `json:"type"`
	Basis           string `json:"basis,omitempty"`
	SourceCollector string `json:"source_collector,omitempty"`
}

type RemediationStep struct {
	Step        int              `json:"step"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	EdgeKind    string           `json:"edge_kind"`
	Source      RemediationActor `json:"source"`
	Target      RemediationActor `json:"target"`
	Channels    []string         `json:"channels"`
	Commands    []string         `json:"commands"`
}

type RemediationActor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type Impact struct {
	Summary         string `json:"summary"`
	BlastRadius     string `json:"blast_radius"`
	DataSensitivity string `json:"data_sensitivity,omitempty"`
}

// AttackPathFromExactEvidence renders only the detector-selected witness
// persisted with the immutable finding snapshot.
func AttackPathFromExactEvidence(f *model.Finding) *AttackPath {
	if f == nil || f.ExactEvidence == nil {
		return nil
	}
	exact := f.ExactEvidence
	path := &AttackPath{
		Nodes: make([]PathNode, 0, len(exact.Nodes)),
		Edges: make([]PathEdge, 0, len(exact.Edges)),
	}
	for _, node := range exact.Nodes {
		kinds := make([]string, len(node.Kinds))
		copy(kinds, node.Kinds)
		properties := graph.PublicFactProperties(node.Properties)
		path.Nodes = append(path.Nodes, PathNode{
			ID:         node.ID,
			Kinds:      kinds,
			Properties: properties,
		})
	}
	for _, edge := range exact.Edges {
		properties := graph.PublicFactProperties(edge.Properties)
		pathEdge := PathEdge{
			Source:     edge.Source,
			Target:     edge.Target,
			Kind:       edge.Kind,
			Properties: properties,
			Synthetic:  edge.Synthetic,
		}
		if edge.Synthetic {
			pathEdge.Provenance = &EdgeProvenance{
				Type:            stringMapVal(edge.Provenance, "type"),
				Basis:           stringMapVal(edge.Provenance, "basis"),
				SourceCollector: stringMapVal(edge.Provenance, "source_collector"),
			}
		}
		path.Edges = append(path.Edges, pathEdge)
	}
	issues := append([]string(nil), exact.Reasons...)
	if !exact.Complete && len(issues) == 0 {
		issues = append(issues, "detector_evidence_incomplete")
	}
	finalizeEvidenceGraph(path, issues)
	markExpectedEvidenceEndpoints(path, f.SourceID, f.TargetID)
	return path
}

func stringMapVal(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, _ := values[key].(string)
	return value
}

var impactTemplates = map[string]struct {
	summary     string
	blastRadius string
}{
	"CAN_REACH": {
		summary:     "Agent %s has an inferred transitive access path to resource %s through the observed trust graph.",
		blastRadius: "Prompts handled by %s may be able to reach %s if the inferred relationships are invocable as modeled.",
	},
	"CAN_REACH_CROSS_PROTOCOL": {
		summary:     "A2A agent %s correlates with the MCP path to %s through a shared host; this is a 50%%-confidence hypothesis, not proven end-to-end invocation.",
		blastRadius: "The correlation identifies a boundary to investigate; it does not establish that %s can invoke %s.",
	},
	"CAN_REACH_CREDENTIAL_CHAIN_OBSERVED": {
		summary:     "Agent %s has a path through a shared LiteLLM gateway to credential %s with observed usable material.",
		blastRadius: "Agent %s can reach observed credential material for %s through the correlated gateway path.",
	},
	"CAN_REACH_CREDENTIAL_CHAIN_REFERENCE": {
		summary:     "Agent %s has a path through a shared LiteLLM gateway to credential reference %s; usable material is not present in this finding evidence.",
		blastRadius: "The path links agent %s to credential reference %s; verify material and exposure evidence before treating it as a credential leak.",
	},
	"CAN_EXFILTRATE_VIA": {
		summary:     "Agent %s has inferred sensitive-data access, and tool %s matched the configured exfiltration-channel predicate.",
		blastRadius: "The matched capability creates a potential output route; this finding is not evidence that data was exfiltrated.",
	},
	"CAN_EXECUTE": {
		summary:     "Tool metadata classifies %s as exposing shell or code execution that may run on host %s.",
		blastRadius: "Confirm the tool implementation and sandbox boundary before treating this metadata-derived route as host compromise.",
	},
	"HAS_ACCESS_TO": {
		summary:     "Tool %s has inferred access to resource %s based on capability matching.",
		blastRadius: "Review the attack path for impact assessment.",
	},
	"SHADOWS": {
		summary:     "Tool %s references tool %s by name from another server, matching the shadowing heuristic.",
		blastRadius: "Review both tool descriptions and server trust before concluding that requests can be intercepted.",
	},
	"POISONED_DESCRIPTION": {
		summary:     "Tool %s matched suspicious instruction patterns in its description.",
		blastRadius: "Pattern matches identify content to review; they do not prove that an agent followed the instructions.",
	},
	"CAN_IMPERSONATE": {
		summary:     "Agent %s has skill-description similarity to agent %s above the impersonation heuristic threshold.",
		blastRadius: "Similarity can confuse discovery or delegation, but does not by itself prove malicious impersonation.",
	},
	"POISONED_INSTRUCTIONS": {
		summary:     "Instruction file %s matched suspicious instruction patterns.",
		blastRadius: "Agents loading the file may be exposed; the pattern match does not prove that the instructions executed.",
	},
}

func BuildImpact(f *model.Finding, path *AttackPath) *Impact {
	edgeKind := f.EdgeKind
	if edgeKind == "CAN_REACH" {
		switch f.Variant {
		case model.FindingVariantCredentialObservedMaterial:
			edgeKind = "CAN_REACH_CREDENTIAL_CHAIN_OBSERVED"
		case model.FindingVariantCredentialReference:
			edgeKind = "CAN_REACH_CREDENTIAL_CHAIN_REFERENCE"
		case model.FindingVariantCrossProtocolHostCorrelation:
			edgeKind = "CAN_REACH_CROSS_PROTOCOL"
		}
	}

	srcName := f.SourceName
	if srcName == "" {
		srcName = f.SourceID
	}
	tgtName := f.TargetName
	if tgtName == "" {
		tgtName = f.TargetID
	}

	tmpl, ok := impactTemplates[edgeKind]
	if !ok {
		return &Impact{
			Summary:     fmt.Sprintf("Composite edge %s detected between %s and %s.", f.EdgeKind, srcName, tgtName),
			BlastRadius: "Review the attack path for impact assessment.",
		}
	}

	impact := &Impact{
		Summary:     formatImpactTemplate(tmpl.summary, srcName, tgtName),
		BlastRadius: formatImpactTemplate(tmpl.blastRadius, srcName, tgtName),
	}
	if path != nil {
		for _, node := range path.Nodes {
			if sensitivity, ok := node.Properties["sensitivity"].(string); ok && sensitivity != "" {
				impact.DataSensitivity = sensitivity
				break
			}
		}
	}
	return impact
}

func formatImpactTemplate(tmpl, srcName, tgtName string) string {
	switch strings.Count(tmpl, "%s") {
	case 0:
		return tmpl
	case 1:
		return fmt.Sprintf(tmpl, srcName)
	default:
		return fmt.Sprintf(tmpl, srcName, tgtName)
	}
}

package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

// findingFingerprint returns a stable 16-char hex fingerprint for a finding
// based on its edge kind and endpoints. Same logical finding across scans
// gets the same ID so triage workflows can track state.
func findingFingerprint(edgeKind, sourceID, targetID string) string {
	h := sha256.Sum256([]byte(edgeKind + "|" + sourceID + "|" + targetID))
	return hex.EncodeToString(h[:])[:16]
}

// Finding is an alias for model.Finding so existing callers (analysis.Finding) keep working.
type Finding = model.Finding

// DetectionSemanticsVersion is the version stamped on every finding's
// DetectionVersion so a finding's derivation (severity policy, detector
// variant vocabulary, prose formatters) is reconstructable. Bump this when
// the meaning of a detection subtype, severity mapping, or edge-kind vocabulary
// changes in a way that alters what a finding asserts.
const DetectionSemanticsVersion = "0.1"

// findingMeta is the typed, role-aware presentation record for one composite
// edge kind. descTmpl uses %SRC% / %TGT% tokens so the source and target are
// rendered in their finding-specific roles instead of positional %s
// placeholders (which silently broke when arg counts drifted).
type findingMeta struct {
	category string
	title    string
	// descTmpl carries %SRC% / %TGT% tokens replaced with the role-appropriate
	// party labels by buildDescription.
	descTmpl string
	owasp    []string
	atlas    []string
	// subtype is the persisted DetectionSubtype identifying the detector
	// variant. Empty means the edge kind is its own subtype.
	subtype string
}

var findingsMeta = map[string]findingMeta{
	"CAN_EXFILTRATE_VIA": {
		category: "Data Exfiltration",
		title:    "Agent can exfiltrate data",
		descTmpl: "Agent %SRC% has access to sensitive data and can exfiltrate it through outbound tool %TGT%.",
		owasp:    []string{"MCP04", "ASI08", "ASI10"},
		// T0024 (AI inference-API extraction) deliberately excluded: this edge
		// models exfiltration through agent tool invocation, not the model.
		atlas: []string{"AML.T0086"},
	},
	"CAN_REACH": {
		category: "Transitive Access",
		title:    "Agent can reach resource",
		descTmpl: "Agent %SRC% has a transitive access path to resource %TGT%.",
		owasp:    []string{"MCP01", "ASI06"},
	},
	"CAN_REACH_CROSS_PROTOCOL": {
		category: "Cross-Protocol Access",
		title:    "Agent can reach resource across protocols",
		descTmpl: "External A2A agent %SRC% can reach MCP resource %TGT% across the A2A→MCP boundary via a co-located delegate.",
		owasp:    []string{"MCP01", "ASI06"},
		subtype:  "cross_protocol_pivot",
	},
	"CAN_REACH_CREDENTIAL_CHAIN": {
		category: "Credential Access",
		title:    "Agent can reach upstream credential",
		descTmpl: "Agent %SRC% can reach upstream provider credential %TGT% through a value_hash collision in a LiteLLM gateway.",
		owasp:    []string{"MCP04", "ASI08"},
		// Intentionally unmapped to ATLAS pending analyst assignment —
		// AgentHound only ships techniques it has verified.
		subtype: "credential_access",
	},
	"POISONED_DESCRIPTION": {
		category: "Prompt Injection",
		title:    "Poisoned tool description",
		descTmpl: "Tool %SRC% has injection patterns in its description.",
		owasp:    []string{"MCP05", "ASI03"},
		atlas:    []string{"AML.T0051", "AML.T0110"},
	},
	"SHADOWS": {
		category: "Tool Shadowing",
		title:    "Tool shadows another tool",
		descTmpl: "Tool %SRC% shadows tool %TGT% on another server.",
		owasp:    []string{"MCP05", "ASI03"},
		atlas:    []string{"AML.T0110"},
	},
	"POISONED_INSTRUCTIONS": {
		category: "Instruction Poisoning",
		title:    "Poisoned instruction file",
		descTmpl: "Instruction file %SRC% contains suspicious patterns.",
		owasp:    []string{"MCP05", "ASI03"},
		atlas:    []string{"AML.T0051"},
	},
	"CAN_IMPERSONATE": {
		category: "Agent Impersonation",
		title:    "Agent can impersonate another agent",
		descTmpl: "Agent %SRC% has skill descriptions highly similar to agent %TGT%.",
		owasp:    []string{"MCP05", "ASI03"},
	},
	"CAN_EXECUTE": {
		category: "Remote Execution",
		title:    "Tool can execute commands on host",
		descTmpl: "Tool %SRC% has shell or code execution capability on host %TGT%.",
		owasp:    []string{"MCP01", "ASI06"},
	},
	"HAS_ACCESS_TO": {
		category: "Resource Access",
		title:    "Tool has access to resource",
		descTmpl: "Tool %SRC% has inferred access to resource %TGT%.",
		owasp:    []string{"MCP04", "ASI08"},
	},
	"CONFUSED_DEPUTY": {
		category: "Authorization Confusion",
		title:    "Confused deputy delegation",
		descTmpl: "Low-auth agent %SRC% delegates to higher-privileged agent %TGT%.",
		owasp:    []string{"ASI06", "MCP04"},
	},
	// CAN_REACH, HAS_ACCESS_TO, CAN_EXECUTE, CAN_IMPERSONATE, and
	// CONFUSED_DEPUTY are intentionally unmapped to ATLAS pending analyst
	// assignment -- AgentHound only ships techniques it has verified.
	"TAINTS": {
		category: "Cross-Tool Taint",
		title:    "Tool taints another tool",
		descTmpl: "Untrusted-input tool %SRC% shares a schema with tool %TGT%, tainting its inputs.",
		owasp:    []string{"MCP05", "ASI03"},
		atlas:    []string{"AML.T0051"},
	},
	"IFC_VIOLATION": {
		category: "Information Flow Violation",
		title:    "Information-flow violation",
		descTmpl: "Untrusted source tool %SRC% reaches sensitive sink %TGT%.",
		owasp:    []string{"MCP05", "ASI08"},
		atlas:    []string{"AML.T0057", "AML.T0086"},
	},
	"POISONS_CONTEXT": {
		category: "Context Poisoning",
		title:    "Tool poisons agent context",
		descTmpl: "Injection-bearing tool %SRC% can poison high-capability tool %TGT%.",
		owasp:    []string{"MCP05", "ASI03"},
		atlas:    []string{"AML.T0051", "AML.T0110"},
	},
}

// party is one endpoint of a finding, carrying enough identity to render a
// role-aware label. label() prefers the human name, falling back to the id.
type party struct {
	name string
	kind string
	id   string
}

func (p party) label() string {
	if p.name != "" {
		return p.name
	}
	return p.id
}

// buildDescription renders a role-aware finding description by substituting
// the source and target labels into the edge kind's template. Unlike the
// prior positional fmt.Sprintf, missing tokens simply do not appear, so an
// arg-count drift can never leak a "%!(EXTRA ...)" wart to the UI.
func buildDescription(descTmpl string, src, tgt party) string {
	r := strings.NewReplacer("%SRC%", src.label(), "%TGT%", tgt.label())
	return r.Replace(descTmpl)
}

// confidenceBasis returns a short human explanation of how a finding's
// confidence was derived, so the operator understands whether a score rests
// on observed facts or a heuristic/synthetic join.
func confidenceBasis(edgeKind string, confidence float64, crossProtocol bool) string {
	switch edgeKind {
	case "CAN_REACH_CREDENTIAL_CHAIN":
		return "Synthetic value_hash join binding an MCP env-var credential to a LiteLLM-exposed upstream key."
	case "CAN_REACH_CROSS_PROTOCOL":
		return "Heuristic A2A→MCP pivot inferred from delegate/host co-location; no observed transitive edge."
	case "CAN_REACH":
		if crossProtocol {
			return "Heuristic cross-protocol reach inferred from host co-location."
		}
		return "Observed transitive path over trusted MCP server, tool, and resource-access edges."
	default:
		return fmt.Sprintf("Derived from observed composite evidence at confidence %.2f.", confidence)
	}
}

const findingsQuery = `
MATCH (src)-[r]->(tgt)
WHERE r.is_composite = true
RETURN src.objectid AS source_id,
       src.name AS source_name,
       labels(src)[0] AS source_kind,
       tgt.objectid AS target_id,
       tgt.name AS target_name,
       labels(tgt)[0] AS target_kind,
       type(r) AS edge_kind,
       r.confidence AS confidence,
       r.cross_protocol AS cross_protocol,
       tgt.sensitivity AS target_sensitivity
ORDER BY r.confidence DESC`

// findingsQueryScoped restricts the composite-edge scan to a single generation
// via the generations set tagged at ingest. It is the snapshot-time query: a
// foreign/stale composite edge left by another scope's generation carries a
// different generation in its set and is excluded, so this generation's
// snapshot cannot re-stamp findings it did not produce.
const findingsQueryScoped = `
MATCH (src)-[r]->(tgt)
WHERE r.is_composite = true AND $gen IN coalesce(r.generations, [])
RETURN src.objectid AS source_id,
       src.name AS source_name,
       labels(src)[0] AS source_kind,
       tgt.objectid AS target_id,
       tgt.name AS target_name,
       labels(tgt)[0] AS target_kind,
       type(r) AS edge_kind,
       r.confidence AS confidence,
       r.cross_protocol AS cross_protocol,
       tgt.sensitivity AS target_sensitivity
ORDER BY r.confidence DESC`

// QueryFindings queries all composite edges and maps them to findings with
// severity. Used by the Postgres-less fallback read path; the generation-
// scoped snapshot uses QueryFindingsScoped.
func QueryFindings(ctx context.Context, db graph.GraphDB, severity string) ([]Finding, error) {
	rows, err := db.Query(ctx, findingsQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	return findingsFromRows(rows, severity), nil
}

// QueryFindingsScoped maps only the composite edges belonging to generationID
// into findings. When generationID is empty it degrades to the unscoped
// QueryFindings so a caller without a generation still gets a result rather
// than an empty snapshot.
func QueryFindingsScoped(ctx context.Context, db graph.GraphDB, severity, generationID string) ([]Finding, error) {
	if generationID == "" {
		return QueryFindings(ctx, db, severity)
	}
	rows, err := db.Query(ctx, findingsQueryScoped, map[string]any{"gen": generationID})
	if err != nil {
		return nil, fmt.Errorf("query findings (generation %s): %w", generationID, err)
	}
	return findingsFromRows(rows, severity), nil
}

// findingsFromRows maps composite-edge result rows into findings, applying the
// optional severity filter. Shared by the scoped and unscoped queries so both
// produce byte-identical finding shapes.
func findingsFromRows(rows []map[string]any, severity string) []Finding {
	var findings []Finding
	for _, row := range rows {
		edgeKind := stringVal(row, "edge_kind")
		sourceID := stringVal(row, "source_id")
		sourceName := stringVal(row, "source_name")
		sourceKind := stringVal(row, "source_kind")
		targetID := stringVal(row, "target_id")
		targetName := stringVal(row, "target_name")
		targetKind := stringVal(row, "target_kind")
		confidence := floatVal(row, "confidence")
		crossProtocol := boolVal(row, "cross_protocol")
		targetSensitivity := stringVal(row, "target_sensitivity")

		sev := classifySeverity(edgeKind, crossProtocol, confidence, targetSensitivity)
		if severity != "" && sev != severity {
			continue
		}

		meta, ok := findingsMeta[edgeKind]
		if !ok {
			meta = findingMeta{
				category: "Other",
				title:    edgeKind + " finding",
				descTmpl: "Composite edge " + edgeKind + " detected between %SRC% and %TGT%.",
			}
		}

		src := party{name: sourceName, kind: sourceKind, id: sourceID}
		tgt := party{name: targetName, kind: targetKind, id: targetID}

		subtype := meta.subtype
		if subtype == "" {
			subtype = strings.ToLower(edgeKind)
		}

		findings = append(findings, Finding{
			ID:               findingFingerprint(edgeKind, sourceID, targetID),
			Severity:         sev,
			Category:         meta.category,
			Title:            meta.title,
			Description:      buildDescription(meta.descTmpl, src, tgt),
			EdgeKind:         edgeKind,
			SourceID:         sourceID,
			SourceName:       sourceName,
			SourceKind:       sourceKind,
			TargetID:         targetID,
			TargetName:       targetName,
			TargetKind:       targetKind,
			Confidence:       confidence,
			OWASPMap:         meta.owasp,
			ATLASMap:         meta.atlas,
			DetectionSubtype: subtype,
			DetectionVersion: DetectionSemanticsVersion,
			ConfidenceBasis:  confidenceBasis(edgeKind, confidence, crossProtocol),
		})
	}

	return findings
}

func classifySeverity(edgeKind string, crossProtocol bool, confidence float64, targetSensitivity string) string {
	switch edgeKind {
	case "CAN_EXFILTRATE_VIA":
		return "critical"
	case "CAN_REACH_CROSS_PROTOCOL":
		// A resource reachable by an unauthenticated external agent across
		// the protocol boundary is always critical regardless of confidence.
		return "critical"
	case "CAN_REACH_CREDENTIAL_CHAIN":
		// Reaching an upstream provider key enables lateral movement to every
		// service the gateway fronts.
		return "critical"
	case "CAN_REACH":
		if crossProtocol {
			return "critical"
		}
		if confidence >= 0.8 && targetSensitivity == "critical" {
			return "critical"
		}
		if targetSensitivity == "high" {
			return "high"
		}
		return "medium"
	case "POISONED_DESCRIPTION", "SHADOWS", "POISONED_INSTRUCTIONS",
		"CONFUSED_DEPUTY", "IFC_VIOLATION", "POISONS_CONTEXT":
		return "high"
	case "CAN_IMPERSONATE", "CAN_EXECUTE", "HAS_ACCESS_TO", "TAINTS":
		return "medium"
	default:
		return "low"
	}
}

func stringVal(row map[string]any, key string) string {
	v, ok := row[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func floatVal(row map[string]any, key string) float64 {
	v, ok := row[key]
	if !ok || v == nil {
		return 0
	}
	switch f := v.(type) {
	case float64:
		return f
	case int64:
		return float64(f)
	default:
		return 0
	}
}

func boolVal(row map[string]any, key string) bool {
	v, ok := row[key]
	if !ok || v == nil {
		return false
	}
	b, _ := v.(bool)
	return b
}

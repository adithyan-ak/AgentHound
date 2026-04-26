package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

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

var findingsMeta = map[string]struct {
	category string
	title    string
	desc     string
	owasp    []string
}{
	"CAN_EXFILTRATE_VIA": {
		category: "Data Exfiltration",
		title:    "Agent can exfiltrate data",
		desc:     "Agent has access to sensitive data and an outbound exfiltration channel via %s",
		owasp:    []string{"MCP04", "ASI08", "ASI10"},
	},
	"CAN_REACH": {
		category: "Transitive Access",
		title:    "Agent can reach resource",
		desc:     "Agent has transitive access path to %s",
		owasp:    []string{"MCP01", "ASI06"},
	},
	"POISONED_DESCRIPTION": {
		category: "Prompt Injection",
		title:    "Poisoned tool description",
		desc:     "Tool %s has injection patterns in its description",
		owasp:    []string{"MCP05", "ASI03"},
	},
	"SHADOWS": {
		category: "Tool Shadowing",
		title:    "Tool shadows another tool",
		desc:     "Tool %s shadows a tool on another server",
		owasp:    []string{"MCP05", "ASI03"},
	},
	"POISONED_INSTRUCTIONS": {
		category: "Instruction Poisoning",
		title:    "Poisoned instruction file",
		desc:     "Instruction file %s contains suspicious patterns",
		owasp:    []string{"MCP05", "ASI03"},
	},
	"CAN_IMPERSONATE": {
		category: "Agent Impersonation",
		title:    "Agent can impersonate another agent",
		desc:     "Agent %s has highly similar skill descriptions to another agent",
		owasp:    []string{"MCP05", "ASI03"},
	},
	"CAN_EXECUTE": {
		category: "Remote Execution",
		title:    "Tool can execute commands on host",
		desc:     "Tool %s has shell or code execution capability on a host",
		owasp:    []string{"MCP01", "ASI06"},
	},
	"HAS_ACCESS_TO": {
		category: "Resource Access",
		title:    "Tool has access to resource",
		desc:     "Tool %s has inferred access to a resource",
		owasp:    []string{"MCP04", "ASI08"},
	},
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

// QueryFindings queries all composite edges and maps them to findings with severity.
func QueryFindings(ctx context.Context, db graph.GraphDB, severity string) ([]Finding, error) {
	rows, err := db.Query(ctx, findingsQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}

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
			meta = struct {
				category string
				title    string
				desc     string
				owasp    []string
			}{
				category: "Other",
				title:    edgeKind + " finding",
				desc:     "Composite edge %s detected",
			}
		}

		descTarget := targetName
		if descTarget == "" {
			descTarget = targetID
		}

		findings = append(findings, Finding{
			ID:          findingFingerprint(edgeKind, sourceID, targetID),
			Severity:    sev,
			Category:    meta.category,
			Title:       meta.title,
			Description: fmt.Sprintf(meta.desc, descTarget),
			EdgeKind:    edgeKind,
			SourceID:    sourceID,
			SourceName:  sourceName,
			SourceKind:  sourceKind,
			TargetID:    targetID,
			TargetName:  targetName,
			TargetKind:  targetKind,
			Confidence:  confidence,
			OWASPMap:    meta.owasp,
		})
	}

	return findings, nil
}

func classifySeverity(edgeKind string, crossProtocol bool, confidence float64, targetSensitivity string) string {
	switch edgeKind {
	case "CAN_EXFILTRATE_VIA":
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
	case "POISONED_DESCRIPTION", "SHADOWS", "POISONED_INSTRUCTIONS":
		return "high"
	case "CAN_IMPERSONATE", "CAN_EXECUTE", "HAS_ACCESS_TO":
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

package analysis

import (
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/server/model"
)

func BuildRemediation(path *AttackPath, f *Finding) []RemediationStep {
	if path == nil || len(path.Edges) == 0 {
		return buildFindingOnlyRemediation(f)
	}

	nodes := make(map[string]PathNode, len(path.Nodes))
	for _, node := range path.Nodes {
		nodes[node.ID] = node
	}
	// Finding-level advice carries detector variant/channel semantics that no
	// individual witness hop can recover. Retain it alongside hop-specific
	// advice instead of discarding it whenever a path is present.
	steps := buildFindingScopedRemediation(f)
	steps = append([]RemediationStep(nil), steps...)
	seen := make(map[string]bool)
	for _, edge := range path.Edges {
		key := edge.Kind + "|" + edge.Source + "|" + edge.Target
		if seen[key] {
			continue
		}
		seen[key] = true
		step, ok := remediationForRelation(edge, nodes[edge.Source], nodes[edge.Target])
		if !ok {
			continue
		}
		step.Step = len(steps) + 1
		steps = append(steps, step)
	}

	if len(steps) == 0 {
		return buildFindingOnlyRemediation(f)
	}

	for i := range steps {
		steps[i].Step = i + 1
	}
	return steps
}

func buildFindingOnlyRemediation(f *Finding) []RemediationStep {
	if scoped := buildFindingScopedRemediation(f); len(scoped) > 0 {
		scoped[0].Step = 1
		return scoped
	}

	source := actorFromFinding(f.SourceID, f.SourceName, f.SourceKind)
	target := actorFromFinding(f.TargetID, f.TargetName, f.TargetKind)
	step := RemediationStep{
		Step:     1,
		EdgeKind: f.EdgeKind,
		Source:   source,
		Target:   target,
	}
	switch f.EdgeKind {
	case "CAN_REACH":
		step.Title = "Review the inferred access chain"
		step.Description = fmt.Sprintf(
			"Apply least privilege between %s and %s. No hop-specific recommendation is generated because exact relationship evidence is unavailable.",
			typedRemediationActor(source, "source"),
			typedRemediationActor(target, "target"),
		)
	default:
		relation := PathEdge{Source: f.SourceID, Target: f.TargetID, Kind: f.EdgeKind}
		generated, ok := remediationForRelation(
			relation,
			PathNode{ID: f.SourceID, Kinds: []string{f.SourceKind}, Properties: map[string]any{"name": f.SourceName}},
			PathNode{ID: f.TargetID, Kinds: []string{f.TargetKind}, Properties: map[string]any{"name": f.TargetName}},
		)
		if !ok {
			// Unsupported remediation is represented as an empty, non-nil
			// collection. The UI renders neutral "no generated
			// recommendation" copy rather than implying no action is needed.
			return []RemediationStep{}
		}
		generated.Step = 1
		return []RemediationStep{generated}
	}
	return []RemediationStep{step}
}

func buildFindingScopedRemediation(f *Finding) []RemediationStep {
	source := actorFromFinding(f.SourceID, f.SourceName, f.SourceKind)
	target := actorFromFinding(f.TargetID, f.TargetName, f.TargetKind)
	step := RemediationStep{
		EdgeKind: f.EdgeKind,
		Source:   source,
		Target:   target,
	}
	switch {
	case f.Variant == model.FindingVariantCredentialObservedMaterial:
		step.Title = "Rotate observed credential material"
		step.Description = fmt.Sprintf(
			"Credential %s has observed exposed material in this finding. Revoke or rotate it, then remove the agent-to-gateway route that exposed it.",
			actorName(target),
		)
	case f.Variant == model.FindingVariantCredentialReference ||
		f.Variant == model.FindingVariantCredentialNodeReference:
		step.Title = "Validate credential material evidence"
		step.Description = fmt.Sprintf(
			"Credential %s is a reference-only finding. Confirm whether usable material exists and is exposed before generating a rotation action.",
			actorName(target),
		)
	case f.Variant == model.FindingVariantCrossProtocolHostCorrelation:
		step.Title = "Validate the cross-protocol correlation"
		step.Description = fmt.Sprintf(
			"Verify that %s and the MCP path to %s are actually co-resident and invocable under the same trust boundary; the shared-host correlation alone is not an execution path.",
			typedRemediationActor(source, "A2A agent"),
			typedRemediationActor(target, "resource"),
		)
	case f.EdgeKind == "CAN_EXFILTRATE_VIA":
		step.Title = "Restrict the matched output channel"
		step.Channels = append([]string(nil), f.Evidence.Channels...)
		channelText := "the configured channel predicate"
		if len(step.Channels) > 0 {
			channelText = strings.Join(step.Channels, ", ")
		}
		step.Description = fmt.Sprintf(
			"Review and restrict %s on %s, and separate it from agents that can reach sensitive resources.",
			channelText,
			typedRemediationActor(target, "tool"),
		)
	default:
		return []RemediationStep{}
	}
	return []RemediationStep{step}
}

func remediationForRelation(
	edge PathEdge,
	sourceNode, targetNode PathNode,
) (RemediationStep, bool) {
	source := actorFromPathNode(sourceNode, edge.Source)
	target := actorFromPathNode(targetNode, edge.Target)
	step := RemediationStep{
		EdgeKind: edge.Kind,
		Source:   source,
		Target:   target,
	}

	switch edge.Kind {
	case "TRUSTS_SERVER":
		step.Title = "Verify server authentication"
		methodRaw, _ := targetNode.Properties["auth_method"].(string)
		method := common.NormalizeAuthMethod(methodRaw)
		authEvidence, _ := targetNode.Properties["auth_evidence"].(string)
		switch method {
		case common.AuthNone:
			if !common.IsConfirmedAnonymousAccess(methodRaw, authEvidence) {
				step.Description = fmt.Sprintf(
					"%s reports auth_method=none, but explicit anonymous-access evidence is unavailable. Verify the configured scheme and server identity used by %s before concluding that it is unauthenticated.",
					typedRemediationActor(target, "MCP server"),
					typedRemediationActor(source, "agent"),
				)
				break
			}
			step.Description = fmt.Sprintf(
				"%s explicitly reports no authentication. Configure an authenticated trust relationship and verify the server identity before %s invokes it.",
				typedRemediationActor(target, "MCP server"),
				typedRemediationActor(source, "agent"),
			)
		case common.AuthUnknown, common.AuthCustom:
			step.Description = fmt.Sprintf(
				"Authentication evidence for %s is %s. Verify the configured scheme and server identity used by %s; no specific authentication upgrade is inferred.",
				typedRemediationActor(target, "MCP server"),
				method,
				typedRemediationActor(source, "agent"),
			)
		default:
			step.Description = fmt.Sprintf(
				"%s reports %s authentication. Verify that %s validates that identity and that the credential scope is least-privileged.",
				typedRemediationActor(target, "MCP server"),
				method,
				typedRemediationActor(source, "agent"),
			)
		}
		step.Commands = []string{"# Review the MCP client trust and authentication configuration"}
	case "PROVIDES_TOOL":
		step.Title = "Review tool exposure"
		step.Description = fmt.Sprintf(
			"Verify that %s needs to expose %s and restrict its input schema and permissions.",
			typedRemediationActor(source, "MCP server"),
			typedRemediationActor(target, "tool"),
		)
	case "HAS_ACCESS_TO":
		step.Title = "Restrict inferred resource access"
		step.Description = fmt.Sprintf(
			"%s has metadata-derived access to %s. Confirm the match, then restrict the tool permission or resource scope.",
			typedRemediationActor(source, "tool"),
			typedRemediationActor(target, "resource"),
		)
	case "CAN_EXECUTE":
		step.Title = "Constrain shell or code execution"
		step.Description = fmt.Sprintf(
			"%s is classified as exposing shell or code execution that may run on %s. Confirm the implementation, then sandbox it or remove the execution capability.",
			typedRemediationActor(source, "tool"),
			typedRemediationActor(target, "host"),
		)
		step.Commands = []string{
			"# Run the MCP server in a least-privileged sandbox",
			"# Remove shell_access/code_execution capability when unnecessary",
		}
	case "SHADOWS":
		step.Title = "Investigate tool shadowing"
		step.Description = fmt.Sprintf(
			"Review why %s references %s by name and verify both server identities before changing trust.",
			typedRemediationActor(source, "tool"),
			typedRemediationActor(target, "tool"),
		)
	case "POISONED_DESCRIPTION":
		step.Title = "Review suspicious tool-description content"
		step.Description = fmt.Sprintf(
			"Inspect the pattern match in %s, remove instruction-like content that is not required, and confirm the owning server before republishing the tool.",
			typedRemediationActor(source, "tool"),
		)
	case "CAN_IMPERSONATE":
		step.Title = "Differentiate agent identities"
		step.Description = fmt.Sprintf(
			"Give %s and %s distinct, verifiable identities and skill descriptions; validate the similarity finding before blocking delegation.",
			typedRemediationActor(source, "agent"),
			typedRemediationActor(target, "agent"),
		)
	case "POISONED_INSTRUCTIONS":
		step.Title = "Review suspicious instruction content"
		step.Description = fmt.Sprintf(
			"Inspect the matched content in %s and remove imperative overrides or hidden payloads that are not authorized.",
			typedRemediationActor(source, "instruction file"),
		)
	case "HAS_ENV_VAR":
		step.Title = "Protect observed credential material"
		material, _ := targetNode.Properties["material_status"].(string)
		exposure, _ := targetNode.Properties["exposure_status"].(string)
		if material == "observed" && exposure == "exposed" {
			step.Description = fmt.Sprintf(
				"%s contains observed exposed material reachable from %s. Move it to a scoped secret reference and rotate the observed value.",
				typedRemediationActor(target, "credential"),
				typedRemediationActor(source, "MCP server"),
			)
		} else {
			step.Description = fmt.Sprintf(
				"%s is not backed by observed exposed material in this evidence. Validate the reference and storage path before generating a rotation action.",
				typedRemediationActor(target, "credential"),
			)
		}
	case "EXPOSES_CREDENTIAL":
		step.Title = "Restrict credential exposure"
		material, _ := targetNode.Properties["material_status"].(string)
		exposure, _ := targetNode.Properties["exposure_status"].(string)
		if material == "observed" && exposure == "exposed" {
			step.Description = fmt.Sprintf(
				"%s exposes observed material for %s. Revoke or rotate the credential and restrict the credential-listing interface.",
				typedRemediationActor(source, "AI service"),
				typedRemediationActor(target, "credential"),
			)
		} else {
			step.Description = fmt.Sprintf(
				"%s exposes a reference for %s, but usable material was not observed. Restrict enumeration and verify material state before rotation.",
				typedRemediationActor(source, "AI service"),
				typedRemediationActor(target, "credential"),
			)
		}
	case "RUNS_ON":
		step.Title = "Review host isolation"
		step.Description = fmt.Sprintf(
			"Verify that %s is appropriately isolated on %s and cannot inherit unrelated service privileges.",
			typedRemediationActor(source, "service"),
			typedRemediationActor(target, "host"),
		)
	default:
		return RemediationStep{}, false
	}
	return step, true
}

func actorFromPathNode(node PathNode, fallbackID string) RemediationActor {
	name, _ := node.Properties["name"].(string)
	kind := ""
	if len(node.Kinds) > 0 {
		kind = node.Kinds[0]
	}
	return actorFromFinding(fallbackID, name, kind)
}

func actorFromFinding(id, name, kind string) RemediationActor {
	if name == "" {
		name = id
	}
	return RemediationActor{ID: id, Name: name, Kind: kind}
}

func actorName(actor RemediationActor) string {
	if actor.Name != "" {
		return actor.Name
	}
	return actor.ID
}

func typedRemediationActor(actor RemediationActor, fallbackRole string) string {
	role := map[string]string{
		"AgentInstance":   "agent",
		"A2AAgent":        "A2A agent",
		"MCPServer":       "MCP server",
		"MCPTool":         "tool",
		"MCPResource":     "resource",
		"Credential":      "credential",
		"Host":            "host",
		"Identity":        "identity",
		"InstructionFile": "instruction file",
		"LiteLLMGateway":  "LiteLLM gateway",
	}[actor.Kind]
	if role == "" {
		role = fallbackRole
	}
	return role + " " + actorName(actor)
}

func buildNodeNameMap(path *AttackPath) map[string]string {
	m := make(map[string]string, len(path.Nodes))
	for _, n := range path.Nodes {
		name, _ := n.Properties["name"].(string)
		if name == "" {
			name = n.ID
		}
		m[n.ID] = name
	}
	return m
}

func interpolateDesc(template, src, tgt string) string {
	argCount := 0
	for i := 0; i < len(template)-1; i++ {
		if template[i] == '%' && template[i+1] == 's' {
			argCount++
		}
	}
	switch argCount {
	case 0:
		return template
	case 1:
		return fmt.Sprintf(template, src)
	default:
		return fmt.Sprintf(template, src, tgt)
	}
}

package analysis

import "fmt"

type remediationTemplate struct {
	Title       string
	Description string
	Commands    []string
}

var remediationByEdgeKind = map[string][]remediationTemplate{
	"TRUSTS_SERVER": {{
		Title:       "Enforce server authentication",
		Description: "Agent trusts server %s with no authentication. Configure OAuth, mTLS, or at minimum a bearer token.",
		Commands:    []string{"# Add auth config to your MCP client config for this server"},
	}},
	"PROVIDES_TOOL": {{
		Title:       "Review tool exposure",
		Description: "Server %s exposes tool %s. Verify this tool is necessary and its input schema is restrictive.",
	}},
	"HAS_ACCESS_TO": {{
		Title:       "Restrict resource access",
		Description: "Tool %s has inferred access to resource %s via capability matching. Restrict tool permissions or resource scope.",
	}},
	"CAN_EXECUTE": {{
		Title:       "Remove shell/code execution capability",
		Description: "Tool %s can execute commands on host %s. Sandbox the server or remove shell_access capability.",
		Commands:    []string{"# Run the MCP server in a sandboxed container", "# Remove shell_access from capability_surface"},
	}},
	"SHADOWS": {{
		Title:       "Investigate tool shadowing",
		Description: "Tool %s references tool %s from another server. Verify the tool description is legitimate.",
	}},
	"POISONED_DESCRIPTION": {{
		Title:       "Remediate poisoned tool description",
		Description: "Tool %s has injection patterns in its description. Remove or sanitize the malicious content.",
		Commands:    []string{"# Inspect the tool description for injection patterns", "# Contact the MCP server maintainer"},
	}},
	"CAN_IMPERSONATE": {{
		Title:       "Differentiate agent identities",
		Description: "Agent %s has highly similar skill descriptions to %s. Ensure agents have distinct, verifiable identities.",
	}},
	"POISONED_INSTRUCTIONS": {{
		Title:       "Clean poisoned instruction file",
		Description: "Instruction file %s contains suspicious patterns. Review and sanitize.",
		Commands:    []string{"# Inspect for suspicious patterns: cat -v <file>", "# Remove imperative overrides and encoded payloads"},
	}},
	"HAS_ENV_VAR": {{
		Title:       "Secure credential exposure",
		Description: "Server exposes credential %s via environment variable. Use a vault reference instead.",
	}},
	"RUNS_ON": {{
		Title:       "Review host exposure",
		Description: "Server/agent runs on host %s. Ensure the host is properly isolated.",
	}},
}

func BuildRemediation(path *AttackPath, f *Finding) []RemediationStep {
	if path == nil || len(path.Edges) == 0 {
		return buildFindingOnlyRemediation(f)
	}

	nodeNames := buildNodeNameMap(path)

	var steps []RemediationStep
	seenEdgeKinds := make(map[string]bool)
	stepNum := 1

	for _, edge := range path.Edges {
		if seenEdgeKinds[edge.Kind] {
			continue
		}
		seenEdgeKinds[edge.Kind] = true

		templates, ok := remediationByEdgeKind[edge.Kind]
		if !ok {
			continue
		}

		for _, tmpl := range templates {
			srcName := nodeNames[edge.Source]
			tgtName := nodeNames[edge.Target]

			steps = append(steps, RemediationStep{
				Step:        stepNum,
				Title:       tmpl.Title,
				Description: interpolateDesc(tmpl.Description, srcName, tgtName),
				EdgeKind:    edge.Kind,
				Commands:    tmpl.Commands,
			})
			stepNum++
		}
	}

	if len(steps) == 0 {
		return buildFindingOnlyRemediation(f)
	}

	return steps
}

func buildFindingOnlyRemediation(f *Finding) []RemediationStep {
	templates, ok := remediationByEdgeKind[f.EdgeKind]
	if !ok {
		return nil
	}

	srcName := f.SourceName
	if srcName == "" {
		srcName = f.SourceID
	}
	tgtName := f.TargetName
	if tgtName == "" {
		tgtName = f.TargetID
	}

	steps := make([]RemediationStep, 0, len(templates))
	for i, tmpl := range templates {
		steps = append(steps, RemediationStep{
			Step:        i + 1,
			Title:       tmpl.Title,
			Description: interpolateDesc(tmpl.Description, srcName, tgtName),
			EdgeKind:    f.EdgeKind,
			Commands:    tmpl.Commands,
		})
	}
	return steps
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

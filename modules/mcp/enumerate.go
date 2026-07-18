package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"sort"
	"strings"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

type ServerResult struct {
	Target      string
	CoverageKey string
	State       ingest.OutcomeState
	Outcomes    []ingest.CollectionOutcome
	Nodes       []ingest.Node
	Edges       []ingest.Edge
	Error       error
}

const defaultMaxItems = 10000

func (c *MCPCollector) enumerateServer(ctx context.Context, spec ServerSpec, scanID string) *ServerResult {
	result := &ServerResult{
		Target:      serverTarget(spec),
		CoverageKey: mcpCoverageKey(spec),
	}
	serverID := computeServerID(spec)

	transport, err := buildTransport(spec, c.insecure)
	if err != nil {
		result.Error = fmt.Errorf("build transport for %s: %w", spec.Name, err)
		result.Nodes = append(result.Nodes, buildUnreachableServerNode(serverID, spec, err.Error()))
		result.Outcomes = append(result.Outcomes, methodOutcome(spec, "initialize", ingest.OutcomeFailed, 0, err))
		result.State = ingest.OutcomeFailed
		return result
	}

	client := mcpsdk.NewClient(
		&mcpsdk.Implementation{Name: "AgentHound", Version: common.CollectorVersion()},
		nil,
	)

	initCtx, initCancel := context.WithTimeout(ctx, c.initTimeout)
	defer initCancel()

	session, err := client.Connect(initCtx, transport, nil)
	if err != nil {
		if spec.Transport == "http" {
			return c.retryWithSSE(ctx, spec, scanID, serverID, err)
		}
		result.Error = fmt.Errorf("connect to %s: %w", spec.Name, err)
		result.Nodes = append(result.Nodes, buildUnreachableServerNode(serverID, spec, err.Error()))
		result.Outcomes = append(result.Outcomes, methodOutcome(spec, "initialize", ingest.OutcomeFailed, 0, err))
		result.State = ingest.OutcomeFailed
		return result
	}
	defer session.Close()

	initResult := session.InitializeResult()

	serverNode := buildServerNode(serverID, spec, initResult, c.engine)
	result.Nodes = append(result.Nodes, serverNode)
	result.Outcomes = append(result.Outcomes, methodOutcome(spec, "initialize", ingest.OutcomeComplete, 1, nil))

	if spec.Transport == "http" && spec.URL != "" {
		hostResult := buildHostNodes(serverID, spec.URL, scanID)
		result.Nodes = append(result.Nodes, hostResult.nodes...)
		result.Edges = append(result.Edges, hostResult.edges...)
	} else if spec.Transport == "stdio" {
		hostID := common.HostNodeID("localhost")
		hostInfo := common.ClassifyHost("localhost")
		result.Nodes = append(result.Nodes, common.NewNode(hostID, []string{"Host"}, map[string]any{
			"hostname": hostInfo.Hostname,
			"ip":       hostInfo.IP,
			"scope":    hostInfo.Scope,
		}))
		result.Edges = append(result.Edges, common.NewEdge(serverID, hostID, "RUNS_ON", "MCPServer", "Host",
			common.DefaultEdgeProps(scanID)))
	}

	caps := initResult.Capabilities

	var untrustedTools map[string]string
	if caps != nil && caps.Tools != nil {
		tools := c.enumerateTools(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, tools.nodes...)
		result.Edges = append(result.Edges, tools.edges...)
		result.Outcomes = append(result.Outcomes, tools.outcome)
		untrustedTools = tools.sourceTrust
	} else {
		result.Outcomes = append(result.Outcomes, methodOutcome(spec, "tools/list", ingest.OutcomeNotApplicable, 0, nil))
	}

	if caps != nil && caps.Resources != nil {
		resources := c.enumerateResources(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, resources.nodes...)
		result.Edges = append(result.Edges, resources.edges...)
		result.Outcomes = append(result.Outcomes, resources.outcome)

		templates := c.enumerateResourceTemplates(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, templates.nodes...)
		result.Edges = append(result.Edges, templates.edges...)
		result.Outcomes = append(result.Outcomes, templates.outcome)
	} else {
		result.Outcomes = append(result.Outcomes,
			methodOutcome(spec, "resources/list", ingest.OutcomeNotApplicable, 0, nil),
			methodOutcome(spec, "resources/templates/list", ingest.OutcomeNotApplicable, 0, nil))
	}

	if caps != nil && caps.Prompts != nil {
		prompts := c.enumeratePrompts(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, prompts.nodes...)
		result.Edges = append(result.Edges, prompts.edges...)
		result.Outcomes = append(result.Outcomes, prompts.outcome)
	} else {
		result.Outcomes = append(result.Outcomes, methodOutcome(spec, "prompts/list", ingest.OutcomeNotApplicable, 0, nil))
	}

	// INGESTS_UNTRUSTED join: a tool tagged with an untrusted source_trust
	// ingests attacker-controllable content, so it taints the resources on
	// the same server. v1 fans out to every resource on the server; a
	// future tightening can match by URI scheme.
	result.Edges = append(result.Edges,
		buildIngestsUntrustedEdges(result.Nodes, untrustedTools, scanID)...)
	finalizeServerResult(result, serverID)

	return result
}

func (c *MCPCollector) retryWithSSE(ctx context.Context, spec ServerSpec, scanID, serverID string, origErr error) *ServerResult {
	result := &ServerResult{
		Target:      serverTarget(spec),
		CoverageKey: mcpCoverageKey(spec),
	}

	sseTransport := buildSSETransport(spec, c.insecure)

	client := mcpsdk.NewClient(
		&mcpsdk.Implementation{Name: "AgentHound", Version: common.CollectorVersion()},
		nil,
	)

	initCtx, initCancel := context.WithTimeout(ctx, c.initTimeout)
	defer initCancel()

	session, err := client.Connect(initCtx, sseTransport, nil)
	if err != nil {
		result.Error = fmt.Errorf("connect to %s (streamable failed: %v, SSE failed: %v)", spec.Name, origErr, err)
		result.Nodes = append(result.Nodes, buildUnreachableServerNode(serverID, spec, err.Error()))
		result.Outcomes = append(result.Outcomes, methodOutcome(spec, "initialize", ingest.OutcomeFailed, 0, result.Error))
		result.State = ingest.OutcomeFailed
		return result
	}
	defer session.Close()

	initResult := session.InitializeResult()

	serverNode := buildServerNode(serverID, spec, initResult, c.engine)
	result.Nodes = append(result.Nodes, serverNode)
	result.Outcomes = append(result.Outcomes, methodOutcome(spec, "initialize", ingest.OutcomeComplete, 1, nil))

	if spec.URL != "" {
		hostResult := buildHostNodes(serverID, spec.URL, scanID)
		result.Nodes = append(result.Nodes, hostResult.nodes...)
		result.Edges = append(result.Edges, hostResult.edges...)
	}

	caps := initResult.Capabilities

	var untrustedTools map[string]string
	if caps != nil && caps.Tools != nil {
		tools := c.enumerateTools(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, tools.nodes...)
		result.Edges = append(result.Edges, tools.edges...)
		result.Outcomes = append(result.Outcomes, tools.outcome)
		untrustedTools = tools.sourceTrust
	} else {
		result.Outcomes = append(result.Outcomes, methodOutcome(spec, "tools/list", ingest.OutcomeNotApplicable, 0, nil))
	}

	if caps != nil && caps.Resources != nil {
		resources := c.enumerateResources(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, resources.nodes...)
		result.Edges = append(result.Edges, resources.edges...)
		result.Outcomes = append(result.Outcomes, resources.outcome)

		templates := c.enumerateResourceTemplates(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, templates.nodes...)
		result.Edges = append(result.Edges, templates.edges...)
		result.Outcomes = append(result.Outcomes, templates.outcome)
	} else {
		result.Outcomes = append(result.Outcomes,
			methodOutcome(spec, "resources/list", ingest.OutcomeNotApplicable, 0, nil),
			methodOutcome(spec, "resources/templates/list", ingest.OutcomeNotApplicable, 0, nil))
	}

	if caps != nil && caps.Prompts != nil {
		prompts := c.enumeratePrompts(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, prompts.nodes...)
		result.Edges = append(result.Edges, prompts.edges...)
		result.Outcomes = append(result.Outcomes, prompts.outcome)
	} else {
		result.Outcomes = append(result.Outcomes, methodOutcome(spec, "prompts/list", ingest.OutcomeNotApplicable, 0, nil))
	}

	// INGESTS_UNTRUSTED join: a tool tagged with an untrusted source_trust
	// ingests attacker-controllable content, so it taints the resources on
	// the same server. v1 fans out to every resource on the server; a
	// future tightening can match by URI scheme.
	result.Edges = append(result.Edges,
		buildIngestsUntrustedEdges(result.Nodes, untrustedTools, scanID)...)
	finalizeServerResult(result, serverID)

	return result
}

type enumResult struct {
	nodes   []ingest.Node
	edges   []ingest.Edge
	outcome ingest.CollectionOutcome
	// sourceTrust maps an untrusted tool's node ID to its rule-derived
	// source_trust label (untrusted_web | untrusted_email |
	// untrusted_fileshare). Populated only by enumerateTools; consumed by
	// the INGESTS_UNTRUSTED join after resources are enumerated.
	sourceTrust map[string]string
}

func (c *MCPCollector) enumerateTools(ctx context.Context, session *mcpsdk.ClientSession, serverID, scanID string) enumResult {
	var result enumResult

	state := ingest.OutcomeComplete
	var outcomeErr error
	tools, truncated, err := observeSessionTools(ctx, session, c.maxItems)
	if err != nil {
		logEnumerationError("tool", serverID, err)
		outcomeErr = err
		if len(tools) > 0 {
			state = ingest.OutcomePartial
		} else {
			state = ingest.OutcomeFailed
		}
	} else if truncated {
		log.Printf("[mcp] tool enumeration hit safety valve (%d items) for server %s", c.maxItems, serverID)
		state = ingest.OutcomeTruncated
	}
	result.outcome = enumerationOutcome(serverID, "tools/list", state, len(tools), outcomeErr)

	allNames := make(map[string]bool, len(tools))
	for _, t := range tools {
		allNames[t.Name] = true
	}

	for _, tool := range tools {
		signals := computeToolSignals(tool, allNames, c.engine)
		toolID := ingest.ComputeNodeID("MCPTool", serverID, tool.Name)

		inputSchemaJSON := marshalJSON(tool.InputSchema)
		props := map[string]any{
			"name":                   tool.Name,
			"description":            tool.Description,
			"input_schema":           inputSchemaJSON,
			"output_schema":          marshalJSON(tool.OutputSchema),
			"description_hash":       signals.DescriptionHash,
			"input_schema_hash":      common.HashSHA256(inputSchemaJSON),
			"capability_surface":     signals.CapabilitySurface,
			"has_injection_patterns": signals.HasInjection,
			"has_cross_references":   signals.HasCrossReferences,
		}
		if signals.Annotations != nil {
			props["annotations"] = signals.Annotations
		}
		if keys := inputSchemaKeys(tool.InputSchema); len(keys) > 0 {
			props["schema_keys"] = keys
		}
		if signals.SourceTrust != "" {
			props["source_trust"] = signals.SourceTrust
			if result.sourceTrust == nil {
				result.sourceTrust = make(map[string]string)
			}
			result.sourceTrust[toolID] = signals.SourceTrust
		}

		result.nodes = append(result.nodes, common.NewNode(toolID, []string{"MCPTool"}, props))
		result.edges = append(result.edges, common.NewEdge(serverID, toolID, "PROVIDES_TOOL", "MCPServer", "MCPTool",
			common.NewEdgeProps(scanID, 1.0, 0.1)))
	}

	return result
}

func (c *MCPCollector) enumerateResources(ctx context.Context, session *mcpsdk.ClientSession, serverID, scanID string) enumResult {
	var result enumResult
	count := 0
	state := ingest.OutcomeComplete
	var outcomeErr error

	for res, err := range session.Resources(ctx, nil) {
		if err != nil {
			logEnumerationError("resource", serverID, err)
			outcomeErr = err
			if count > 0 {
				state = ingest.OutcomePartial
			} else {
				state = ingest.OutcomeFailed
			}
			break
		}
		count++
		if count > c.maxItems {
			log.Printf("[mcp] resource enumeration hit safety valve (%d items) for server %s", c.maxItems, serverID)
			state = ingest.OutcomeTruncated
			break
		}

		signals := computeResourceSignals(res.URI, c.engine)
		resID := ingest.ComputeNodeID("MCPResource", serverID, res.URI)

		result.nodes = append(result.nodes, common.NewNode(resID, []string{"MCPResource"}, map[string]any{
			"uri":                  res.URI,
			"name":                 res.Name,
			"mime_type":            res.MIMEType,
			"size":                 res.Size,
			"description":          res.Description,
			"uri_scheme":           signals.URIScheme,
			"sensitivity":          signals.Sensitivity,
			"sensitivity_rule_id":  signals.SensitivityRuleID,
			"sensitivity_evidence": signals.SensitivityEvidence,
		}))
		result.edges = append(result.edges, common.NewEdge(serverID, resID, "PROVIDES_RESOURCE", "MCPServer", "MCPResource",
			common.NewEdgeProps(scanID, 1.0, 0.2)))
	}
	result.outcome = enumerationOutcome(serverID, "resources/list", state, len(result.nodes), outcomeErr)

	return result
}

func (c *MCPCollector) enumerateResourceTemplates(ctx context.Context, session *mcpsdk.ClientSession, serverID, scanID string) enumResult {
	var result enumResult
	count := 0
	state := ingest.OutcomeComplete
	var outcomeErr error

	for tmpl, err := range session.ResourceTemplates(ctx, nil) {
		if err != nil {
			logEnumerationError("resource template", serverID, err)
			outcomeErr = err
			if count > 0 {
				state = ingest.OutcomePartial
			} else {
				state = ingest.OutcomeFailed
			}
			break
		}
		count++
		if count > c.maxItems {
			log.Printf("[mcp] resource template enumeration hit safety valve (%d items) for server %s", c.maxItems, serverID)
			state = ingest.OutcomeTruncated
			break
		}

		signals := computeResourceSignals(tmpl.URITemplate, c.engine)
		resID := ingest.ComputeNodeID("MCPResource", serverID, tmpl.URITemplate)

		result.nodes = append(result.nodes, common.NewNode(resID, []string{"MCPResource"}, map[string]any{
			"uri":                  tmpl.URITemplate,
			"name":                 tmpl.Name,
			"mime_type":            tmpl.MIMEType,
			"description":          tmpl.Description,
			"uri_scheme":           signals.URIScheme,
			"sensitivity":          signals.Sensitivity,
			"sensitivity_rule_id":  signals.SensitivityRuleID,
			"sensitivity_evidence": signals.SensitivityEvidence,
			"is_template":          true,
		}))
		result.edges = append(result.edges, common.NewEdge(serverID, resID, "PROVIDES_RESOURCE", "MCPServer", "MCPResource",
			common.NewEdgeProps(scanID, 1.0, 0.2)))
	}
	result.outcome = enumerationOutcome(serverID, "resources/templates/list", state, len(result.nodes), outcomeErr)

	return result
}

func (c *MCPCollector) enumeratePrompts(ctx context.Context, session *mcpsdk.ClientSession, serverID, scanID string) enumResult {
	var result enumResult
	count := 0
	state := ingest.OutcomeComplete
	var outcomeErr error

	for prompt, err := range session.Prompts(ctx, nil) {
		if err != nil {
			logEnumerationError("prompt", serverID, err)
			outcomeErr = err
			if count > 0 {
				state = ingest.OutcomePartial
			} else {
				state = ingest.OutcomeFailed
			}
			break
		}
		count++
		if count > c.maxItems {
			log.Printf("[mcp] prompt enumeration hit safety valve (%d items) for server %s", c.maxItems, serverID)
			state = ingest.OutcomeTruncated
			break
		}

		promptID := ingest.ComputeNodeID("MCPPrompt", serverID, prompt.Name)

		result.nodes = append(result.nodes, common.NewNode(promptID, []string{"MCPPrompt"}, map[string]any{
			"name":        prompt.Name,
			"description": prompt.Description,
			"arguments":   marshalJSON(prompt.Arguments),
		}))
		result.edges = append(result.edges, common.NewEdge(serverID, promptID, "PROVIDES_PROMPT", "MCPServer", "MCPPrompt",
			common.NewEdgeProps(scanID, 1.0, 0.1)))
	}
	result.outcome = enumerationOutcome(serverID, "prompts/list", state, len(result.nodes), outcomeErr)

	return result
}

func computeServerID(spec ServerSpec) string {
	return serverIdentityForSpec(spec).ObjectID
}

func mcpCoverageKey(spec ServerSpec) string {
	scope := computeServerID(spec)
	if spec.Transport == "http" {
		scope = ingest.CanonicalURLScope(spec.URL)
	}
	return ingest.CanonicalCoverageKey("mcp", "target", scope)
}

func serverIdentityForSpec(spec ServerSpec) ingest.MCPServerIdentity {
	if spec.Transport == "http" {
		return ingest.ResolveMCPServerIdentity("http", spec.URL)
	}
	return ingest.ResolveMCPServerIdentity("stdio", spec.Command, spec.Args...)
}

func buildServerNode(serverID string, spec ServerSpec, initResult *mcpsdk.InitializeResult, engine *rules.Engine) ingest.Node {
	endpoint := spec.Command
	if spec.Transport == "http" {
		endpoint = spec.URL
	}

	var capabilities []string
	if initResult.Capabilities != nil {
		if initResult.Capabilities.Tools != nil {
			capabilities = append(capabilities, "tools")
		}
		if initResult.Capabilities.Resources != nil {
			capabilities = append(capabilities, "resources")
		}
		if initResult.Capabilities.Prompts != nil {
			capabilities = append(capabilities, "prompts")
		}
		if initResult.Capabilities.Logging != nil {
			capabilities = append(capabilities, "logging")
		}
		if initResult.Capabilities.Completions != nil {
			capabilities = append(capabilities, "completions")
		}
	}

	serverName := spec.Name
	if initResult.ServerInfo != nil && initResult.ServerInfo.Name != "" {
		serverName = initResult.ServerInfo.Name
	}

	serverVersion := ""
	if initResult.ServerInfo != nil {
		serverVersion = initResult.ServerInfo.Version
	}

	authMethod, authEvidence := observedServerAuth(spec)
	authAssessment := common.AssessAuth(string(authMethod))
	identity := serverIdentityForSpec(spec)
	props := map[string]any{
		"name":             serverName,
		"endpoint":         endpoint,
		"transport":        spec.Transport,
		"protocol_version": initResult.ProtocolVersion,
		"instructions":     initResult.Instructions,
		"capabilities":     capabilities,
		"server_version":   serverVersion,
		"status":           "reachable",
		"auth_method":      string(authMethod),
		"auth_assurance":   string(authAssessment.Assurance),
		"auth_evidence":    authEvidence,
		"id_scheme":        identity.Scheme,
	}
	if spec.Transport == "stdio" {
		props["command"] = spec.Command
		props["args"] = append([]string(nil), spec.Args...)
	}

	if initResult.Instructions != "" {
		hasInjection := false
		matches := engine.EvaluateAll("mcp", map[string]string{
			"server.instructions": initResult.Instructions,
		})
		for _, m := range matches {
			if m.Emit.FindingType == "has_injection_patterns" {
				hasInjection = true
				break
			}
		}
		props["instructions_has_injection"] = hasInjection
		props["instructions_hash"] = common.HashSHA256(initResult.Instructions)
	}

	return common.NewNode(serverID, []string{"MCPServer"}, props)
}

func buildUnreachableServerNode(serverID string, spec ServerSpec, errMsg string) ingest.Node {
	endpoint := spec.Command
	if spec.Transport == "http" {
		endpoint = spec.URL
	}

	identity := serverIdentityForSpec(spec)
	props := map[string]any{
		"name":           spec.Name,
		"endpoint":       endpoint,
		"transport":      spec.Transport,
		"status":         "unreachable",
		"error":          errMsg,
		"auth_method":    string(common.AuthUnknown),
		"auth_assurance": string(common.AuthAssuranceUnknown),
		"auth_evidence":  common.AuthEvidenceUnknown,
		"id_scheme":      identity.Scheme,
	}
	if spec.Transport == "stdio" {
		props["command"] = spec.Command
		props["args"] = append([]string(nil), spec.Args...)
	}
	return common.NewNode(serverID, []string{"MCPServer"}, props)
}

type hostResult struct {
	nodes []ingest.Node
	edges []ingest.Edge
}

func buildHostNodes(serverID, serverURL, scanID string) hostResult {
	var result hostResult
	hostInfo := common.ClassifyHost(serverURL)
	hostname := hostInfo.Hostname
	if hostname == "" {
		hostname = hostInfo.IP
	}
	if hostname == "" {
		return result
	}

	hostID := common.HostNodeID(hostname)
	result.nodes = append(result.nodes, common.NewNode(hostID, []string{"Host"}, map[string]any{
		"hostname": hostInfo.Hostname,
		"ip":       hostInfo.IP,
		"scope":    hostInfo.Scope,
	}))
	result.edges = append(result.edges, common.NewEdge(serverID, hostID, "RUNS_ON", "MCPServer", "Host",
		common.DefaultEdgeProps(scanID)))

	return result
}

// buildIngestsUntrustedEdges emits INGESTS_UNTRUSTED (MCPTool ->
// MCPResource) for every untrusted tool against every resource discovered
// on the same server. The edge is a RAW edge (is_composite=false) keyed on
// (source, target), so re-scans rewrite scan_id idempotently. v1 is a
// server-scoped fan-out; resource URI-scheme matching is a future
// tightening (see docs/architecture/post-processors.md).
func buildIngestsUntrustedEdges(nodes []ingest.Node, untrustedTools map[string]string, scanID string) []ingest.Edge {
	if len(untrustedTools) == 0 {
		return nil
	}
	var resourceIDs []string
	for _, n := range nodes {
		for _, k := range n.Kinds {
			if k == "MCPResource" {
				resourceIDs = append(resourceIDs, n.ID)
				break
			}
		}
	}
	if len(resourceIDs) == 0 {
		return nil
	}

	// Deterministic ordering so repeated scans emit edges in a stable
	// order (the graph is MERGE-keyed, but stable output aids testing).
	toolIDs := make([]string, 0, len(untrustedTools))
	for id := range untrustedTools {
		toolIDs = append(toolIDs, id)
	}
	sort.Strings(toolIDs)

	var edges []ingest.Edge
	for _, toolID := range toolIDs {
		for _, resID := range resourceIDs {
			props := common.NewEdgeProps(scanID, 0.6, 0.3)
			props["source_trust"] = untrustedTools[toolID]
			edges = append(edges, common.NewEdge(toolID, resID, "INGESTS_UNTRUSTED", "MCPTool", "MCPResource", props))
		}
	}
	return edges
}

func observedServerAuth(spec ServerSpec) (common.AuthMethod, string) {
	if spec.Transport == "stdio" {
		// Starting a local child process proves process-local access, not
		// anonymous network access.
		return common.AuthUnknown, common.AuthEvidenceLocalProcess
	}
	for name, value := range spec.Headers {
		if !strings.EqualFold(name, "Authorization") || strings.TrimSpace(value) == "" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) > 0 {
			if method, ok := common.RecognizeAuthMethod(fields[0]); ok &&
				method != common.AuthNone && method != common.AuthUnknown {
				return method, common.AuthEvidenceConfiguredCredential
			}
		}
		return common.AuthCustom, common.AuthEvidenceConfiguredCredential
	}
	for name, value := range spec.Headers {
		upper := strings.ToUpper(name)
		if strings.TrimSpace(value) != "" &&
			(strings.Contains(upper, "KEY") || strings.Contains(upper, "TOKEN") ||
				strings.Contains(upper, "SECRET") || strings.Contains(upper, "AUTH")) {
			return common.AuthAPIKey, common.AuthEvidenceConfiguredCredential
		}
	}
	// A successful MCP initialize without credential-bearing headers is direct
	// positive evidence that this access path is anonymous.
	return common.AuthNone, common.AuthEvidenceAnonymousProbeSucceeded
}

func serverTarget(spec ServerSpec) string {
	if spec.Transport == "http" {
		return spec.URL
	}
	if len(spec.Args) == 0 {
		return spec.Command
	}
	return spec.Command + " " + strings.Join(spec.Args, " ")
}

func methodOutcome(
	spec ServerSpec,
	method string,
	state ingest.OutcomeState,
	items int,
	err error,
) ingest.CollectionOutcome {
	outcome := ingest.CollectionOutcome{
		Collector:   "mcp",
		CoverageKey: mcpCoverageKey(spec),
		Target:      serverTarget(spec),
		Method:      method,
		State:       state,
		Items:       items,
	}
	if err != nil {
		outcome.Error = err.Error()
	}
	return outcome
}

func enumerationOutcome(
	serverID, method string,
	state ingest.OutcomeState,
	items int,
	err error,
) ingest.CollectionOutcome {
	outcome := ingest.CollectionOutcome{
		Collector:   "mcp",
		CoverageKey: ingest.CanonicalCoverageKey("mcp", "target", serverID),
		Target:      serverID,
		Method:      method,
		State:       state,
		Items:       items,
	}
	if err != nil {
		outcome.Error = err.Error()
	}
	return outcome
}

func finalizeServerResult(result *ServerResult, serverID string) {
	result.State = ingest.AggregateOutcomeState(result.Outcomes)
	for i := range result.Nodes {
		node := &result.Nodes[i]
		if node.ID == serverID {
			node.Properties["collection_state"] = string(result.State)
		}
	}
}

func marshalJSON(v any) string {
	if v == nil {
		return ""
	}
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

func logEnumerationError(kind, serverID string, err error) {
	msg := err.Error()
	if strings.Contains(msg, "Method not found") || strings.Contains(msg, "method not found") {
		slog.Debug("server does not support optional method", "method", methodForKind(kind), "server", serverID)
		return
	}
	log.Printf("[mcp] %s enumeration error for server %s: %v", kind, serverID, err)
}

// methodForKind maps an enumeration kind to the real MCP JSON-RPC method name
// (e.g. "resource template" -> "resources/templates/list") for accurate logs.
func methodForKind(kind string) string {
	switch kind {
	case "tool":
		return "tools/list"
	case "resource":
		return "resources/list"
	case "resource template":
		return "resources/templates/list"
	case "prompt":
		return "prompts/list"
	default:
		return kind + "/list"
	}
}

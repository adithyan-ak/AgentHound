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
	Nodes []ingest.Node
	Edges []ingest.Edge
	Error error
}

const defaultMaxItems = 10000

func (c *MCPCollector) enumerateServer(ctx context.Context, spec ServerSpec, scanID string) *ServerResult {
	result := &ServerResult{}
	serverID := computeServerID(spec)

	transport, err := buildTransport(spec, c.insecure)
	if err != nil {
		result.Error = fmt.Errorf("build transport for %s: %w", spec.Name, err)
		result.Nodes = append(result.Nodes, buildUnreachableServerNode(serverID, spec, err.Error()))
		return result
	}

	client := mcpsdk.NewClient(
		&mcpsdk.Implementation{Name: "AgentHound", Version: common.CollectorVersion},
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
		return result
	}
	defer session.Close()

	initResult := session.InitializeResult()

	serverNode := buildServerNode(serverID, spec, initResult, c.engine)
	result.Nodes = append(result.Nodes, serverNode)

	if spec.Transport == "http" && spec.URL != "" {
		hostResult := buildHostNodes(serverID, spec.URL, scanID)
		result.Nodes = append(result.Nodes, hostResult.nodes...)
		result.Edges = append(result.Edges, hostResult.edges...)
	} else if spec.Transport == "stdio" {
		hostID := common.HostNodeID("localhost")
		hostInfo := common.ClassifyHost("localhost")
		result.Nodes = append(result.Nodes, common.NewNode(hostID, []string{"Host"}, map[string]any{
			"hostname":   hostInfo.Hostname,
			"ip":         hostInfo.IP,
			"is_local":   hostInfo.IsLocal,
			"is_private": hostInfo.IsPrivate,
			"is_public":  hostInfo.IsPublic,
		}))
		result.Edges = append(result.Edges, common.NewEdge(serverID, hostID, "RUNS_ON", "MCPServer", "Host",
			common.DefaultEdgeProps(scanID)))
	}

	caps := initResult.Capabilities

	if caps != nil && caps.Tools != nil {
		tools := c.enumerateTools(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, tools.nodes...)
		result.Edges = append(result.Edges, tools.edges...)
	}

	if caps != nil && caps.Resources != nil {
		resources := c.enumerateResources(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, resources.nodes...)
		result.Edges = append(result.Edges, resources.edges...)

		templates := c.enumerateResourceTemplates(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, templates.nodes...)
		result.Edges = append(result.Edges, templates.edges...)
	}

	if caps != nil && caps.Prompts != nil {
		prompts := c.enumeratePrompts(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, prompts.nodes...)
		result.Edges = append(result.Edges, prompts.edges...)
	}

	return result
}

func (c *MCPCollector) retryWithSSE(ctx context.Context, spec ServerSpec, scanID, serverID string, origErr error) *ServerResult {
	result := &ServerResult{}

	sseTransport := buildSSETransport(spec, c.insecure)

	client := mcpsdk.NewClient(
		&mcpsdk.Implementation{Name: "AgentHound", Version: common.CollectorVersion},
		nil,
	)

	initCtx, initCancel := context.WithTimeout(ctx, c.initTimeout)
	defer initCancel()

	session, err := client.Connect(initCtx, sseTransport, nil)
	if err != nil {
		result.Error = fmt.Errorf("connect to %s (streamable failed: %v, SSE failed: %v)", spec.Name, origErr, err)
		result.Nodes = append(result.Nodes, buildUnreachableServerNode(serverID, spec, err.Error()))
		return result
	}
	defer session.Close()

	initResult := session.InitializeResult()

	serverNode := buildServerNode(serverID, spec, initResult, c.engine)
	result.Nodes = append(result.Nodes, serverNode)

	if spec.URL != "" {
		hostResult := buildHostNodes(serverID, spec.URL, scanID)
		result.Nodes = append(result.Nodes, hostResult.nodes...)
		result.Edges = append(result.Edges, hostResult.edges...)
	}

	caps := initResult.Capabilities

	if caps != nil && caps.Tools != nil {
		tools := c.enumerateTools(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, tools.nodes...)
		result.Edges = append(result.Edges, tools.edges...)
	}

	if caps != nil && caps.Resources != nil {
		resources := c.enumerateResources(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, resources.nodes...)
		result.Edges = append(result.Edges, resources.edges...)

		templates := c.enumerateResourceTemplates(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, templates.nodes...)
		result.Edges = append(result.Edges, templates.edges...)
	}

	if caps != nil && caps.Prompts != nil {
		prompts := c.enumeratePrompts(ctx, session, serverID, scanID)
		result.Nodes = append(result.Nodes, prompts.nodes...)
		result.Edges = append(result.Edges, prompts.edges...)
	}

	return result
}

type enumResult struct {
	nodes []ingest.Node
	edges []ingest.Edge
}

func (c *MCPCollector) enumerateTools(ctx context.Context, session *mcpsdk.ClientSession, serverID, scanID string) enumResult {
	var result enumResult

	var tools []*mcpsdk.Tool
	count := 0
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			logEnumerationError("tool", serverID, err)
			break
		}
		count++
		if count > c.maxItems {
			log.Printf("[mcp] tool enumeration hit safety valve (%d items) for server %s", c.maxItems, serverID)
			break
		}
		tools = append(tools, tool)
	}

	allNames := make(map[string]bool, len(tools))
	for _, t := range tools {
		allNames[t.Name] = true
	}

	for _, tool := range tools {
		signals := computeToolSignals(tool, allNames, c.engine)
		toolID := ingest.ComputeNodeID("MCPTool", serverID, tool.Name)

		props := map[string]any{
			"name":                   tool.Name,
			"description":            tool.Description,
			"input_schema":           marshalJSON(tool.InputSchema),
			"output_schema":          marshalJSON(tool.OutputSchema),
			"description_hash":       signals.DescriptionHash,
			"capability_surface":     signals.CapabilitySurface,
			"has_injection_patterns": signals.HasInjection,
			"has_cross_references":   signals.HasCrossReferences,
		}
		if signals.Annotations != nil {
			props["annotations"] = signals.Annotations
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

	for res, err := range session.Resources(ctx, nil) {
		if err != nil {
			logEnumerationError("resource", serverID, err)
			break
		}
		count++
		if count > c.maxItems {
			log.Printf("[mcp] resource enumeration hit safety valve (%d items) for server %s", c.maxItems, serverID)
			break
		}

		signals := computeResourceSignals(res.URI, c.engine)
		resID := ingest.ComputeNodeID("MCPResource", serverID, res.URI)

		result.nodes = append(result.nodes, common.NewNode(resID, []string{"MCPResource"}, map[string]any{
			"uri":         res.URI,
			"name":        res.Name,
			"mime_type":   res.MIMEType,
			"size":        res.Size,
			"description": res.Description,
			"uri_scheme":  signals.URIScheme,
			"sensitivity": signals.Sensitivity,
		}))
		result.edges = append(result.edges, common.NewEdge(serverID, resID, "PROVIDES_RESOURCE", "MCPServer", "MCPResource",
			common.NewEdgeProps(scanID, 1.0, 0.2)))
	}

	return result
}

func (c *MCPCollector) enumerateResourceTemplates(ctx context.Context, session *mcpsdk.ClientSession, serverID, scanID string) enumResult {
	var result enumResult
	count := 0

	for tmpl, err := range session.ResourceTemplates(ctx, nil) {
		if err != nil {
			logEnumerationError("resource template", serverID, err)
			break
		}
		count++
		if count > c.maxItems {
			log.Printf("[mcp] resource template enumeration hit safety valve (%d items) for server %s", c.maxItems, serverID)
			break
		}

		signals := computeResourceSignals(tmpl.URITemplate, c.engine)
		resID := ingest.ComputeNodeID("MCPResource", serverID, tmpl.URITemplate)

		result.nodes = append(result.nodes, common.NewNode(resID, []string{"MCPResource"}, map[string]any{
			"uri":         tmpl.URITemplate,
			"name":        tmpl.Name,
			"mime_type":   tmpl.MIMEType,
			"description": tmpl.Description,
			"uri_scheme":  signals.URIScheme,
			"sensitivity": signals.Sensitivity,
			"is_template": true,
		}))
		result.edges = append(result.edges, common.NewEdge(serverID, resID, "PROVIDES_RESOURCE", "MCPServer", "MCPResource",
			common.NewEdgeProps(scanID, 1.0, 0.2)))
	}

	return result
}

func (c *MCPCollector) enumeratePrompts(ctx context.Context, session *mcpsdk.ClientSession, serverID, scanID string) enumResult {
	var result enumResult
	count := 0

	for prompt, err := range session.Prompts(ctx, nil) {
		if err != nil {
			logEnumerationError("prompt", serverID, err)
			break
		}
		count++
		if count > c.maxItems {
			log.Printf("[mcp] prompt enumeration hit safety valve (%d items) for server %s", c.maxItems, serverID)
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

	return result
}

func computeServerID(spec ServerSpec) string {
	if spec.Transport == "http" {
		return ingest.ComputeMCPServerID("http", spec.URL)
	}
	sorted := make([]string, len(spec.Args))
	copy(sorted, spec.Args)
	sort.Strings(sorted)
	return ingest.ComputeMCPServerID("stdio", spec.Command, sorted...)
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

	props := map[string]any{
		"name":             serverName,
		"endpoint":         endpoint,
		"transport":        spec.Transport,
		"protocol_version": initResult.ProtocolVersion,
		"instructions":     initResult.Instructions,
		"capabilities":     capabilities,
		"server_version":   serverVersion,
		"status":           "reachable",
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

	return common.NewNode(serverID, []string{"MCPServer"}, map[string]any{
		"name":      spec.Name,
		"endpoint":  endpoint,
		"transport": spec.Transport,
		"status":    "unreachable",
		"error":     errMsg,
	})
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
		"hostname":   hostInfo.Hostname,
		"ip":         hostInfo.IP,
		"is_local":   hostInfo.IsLocal,
		"is_private": hostInfo.IsPrivate,
		"is_public":  hostInfo.IsPublic,
	}))
	result.edges = append(result.edges, common.NewEdge(serverID, hostID, "RUNS_ON", "MCPServer", "Host",
		common.DefaultEdgeProps(scanID)))

	return result
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
		slog.Debug("server does not support optional method", "method", kind+"/list", "server", serverID)
		return
	}
	log.Printf("[mcp] %s enumeration error for server %s: %v", kind, serverID, err)
}

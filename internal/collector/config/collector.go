package config

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	collector "github.com/adithyan-ak/agenthound/internal/collector"
	"github.com/adithyan-ak/agenthound/internal/collector/common"
	"github.com/adithyan-ak/agenthound/internal/model"
	"github.com/adithyan-ak/agenthound/internal/rules"
)

type ConfigCollector struct {
	parsers []ConfigParser
}

func NewConfigCollector() *ConfigCollector {
	return &ConfigCollector{
		parsers: []ConfigParser{
			&ClaudeDesktopParser{},
			&ClaudeCodeParser{},
			&CursorParser{},
			&VSCodeParser{},
			&WindsurfParser{},
			&ContinueParser{},
			&ZedParser{},
			&ClineParser{},
			&JetBrainsParser{},
			&KiroParser{},
			&AmazonQParser{},
			&AugmentParser{},
		},
	}
}

var _ collector.Collector = (*ConfigCollector)(nil)

func (c *ConfigCollector) Name() string { return "config" }

func (c *ConfigCollector) Collect(ctx context.Context, opts collector.CollectOptions) (*model.IngestData, error) {
	engine := opts.RulesEngine
	if engine == nil {
		var engineErr error
		engine, engineErr = rules.NewEngine(rules.LoadOptions{})
		if engineErr != nil {
			return nil, fmt.Errorf("rules engine: %w", engineErr)
		}
	}

	scanID := opts.ScanID
	if scanID == "" {
		scanID = common.GenerateScanID("config")
	}
	data := common.NewIngestData("config", scanID)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	configs, err := c.discoverConfigs(ctx, opts, homeDir)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	addNode := func(n model.Node) {
		if seen[n.ID] {
			return
		}
		seen[n.ID] = true
		data.Graph.Nodes = append(data.Graph.Nodes, n)
	}
	addEdge := func(e model.Edge) {
		data.Graph.Edges = append(data.Graph.Edges, e)
	}

	var agentIDs []string

	for _, cfg := range configs {
		absPath, _ := filepath.Abs(cfg.Path)
		configFileID := model.ComputeNodeID("ConfigFile", absPath)

		activeCount := 0
		for _, s := range cfg.Servers {
			if !s.Disabled {
				activeCount++
			}
		}

		addNode(common.NewNode(configFileID, []string{"ConfigFile"}, map[string]any{
			"path":         absPath,
			"client":       cfg.Client,
			"server_count": activeCount,
		}))

		agentID := model.ComputeNodeID("AgentInstance", configFileID, cfg.Client)
		addNode(common.NewNode(agentID, []string{"AgentInstance"}, map[string]any{
			"name":        cfg.Client,
			"framework":   cfg.Client,
			"config_path": absPath,
		}))
		agentIDs = append(agentIDs, agentID)

		for _, srv := range cfg.Servers {
			if srv.Disabled {
				continue
			}

			serverID := computeServerID(srv)
			endpoint := srv.Command
			if srv.Transport == "http" {
				endpoint = srv.URL
			}

			authMethod := deriveAuthMethod(srv.Env, srv.Headers)
			isPinned := true
			if srv.Transport == "stdio" {
				isPinned = !IsUnpinned(srv.Command, srv.Args)
			}

			addNode(common.NewNode(serverID, []string{"MCPServer"}, map[string]any{
				"name":        srv.Name,
				"endpoint":    endpoint,
				"transport":   srv.Transport,
				"auth_method": authMethod,
				"is_pinned":   isPinned,
			}))

			trustWeight := authRiskWeight(authMethod)
			addEdge(common.NewEdge(agentID, serverID, "TRUSTS_SERVER", "AgentInstance", "MCPServer",
				common.NewEdgeProps(scanID, 1.0, trustWeight)))

			addEdge(common.NewEdge(serverID, configFileID, "CONFIGURED_IN", "MCPServer", "ConfigFile",
				common.DefaultEdgeProps(scanID)))

			hostName := hostForServer(srv)
			hostID := common.HostNodeID(hostName)
			hostInfo := common.ClassifyHost(hostName)
			addNode(common.NewNode(hostID, []string{"Host"}, map[string]any{
				"hostname":   hostInfo.Hostname,
				"ip":         hostInfo.IP,
				"is_local":   hostInfo.IsLocal,
				"is_private": hostInfo.IsPrivate,
				"is_public":  hostInfo.IsPublic,
			}))
			addEdge(common.NewEdge(serverID, hostID, "RUNS_ON", "MCPServer", "Host",
				common.DefaultEdgeProps(scanID)))

			creds := ExtractCredentials(srv.Env, srv.Headers, srv.Name, opts.IncludeCredentialValues, engine)
			for _, cred := range creds {
				identityType := credToIdentityType(cred)
				identityID := model.ComputeNodeID("Identity", serverID, identityType)
				addNode(common.NewNode(identityID, []string{"Identity"}, map[string]any{
					"type":      identityType,
					"scope":     srv.Name,
					"is_static": cred.Type == "hardcoded",
				}))

				credID := model.ComputeNodeID("Credential", cred.Source, cred.Name)
				addNode(common.NewNode(credID, []string{"Credential"}, map[string]any{
					"type":         cred.Type,
					"name":         cred.Name,
					"value":        cred.Value,
					"source":       cred.Source,
					"is_exposed":   cred.IsExposed,
					"high_entropy": cred.HighEntropy,
					"format":       cred.Format,
				}))

				authWeight := identityAuthWeight(identityType)
				addEdge(common.NewEdge(serverID, identityID, "AUTHENTICATES_WITH", "MCPServer", "Identity",
					common.NewEdgeProps(scanID, 1.0, authWeight)))
				addEdge(common.NewEdge(identityID, credID, "USES_CREDENTIAL", "Identity", "Credential",
					common.NewEdgeProps(scanID, 1.0, 0.5)))

				if cred.Type == "hardcoded" || cred.Type == "envVar" {
					addEdge(common.NewEdge(serverID, credID, "HAS_ENV_VAR", "MCPServer", "Credential",
						common.DefaultEdgeProps(scanID)))
				}
			}
		}
	}

	instructions := DiscoverInstructionFiles(homeDir, opts.ProjectDir, engine)
	for _, inst := range instructions {
		absPath, _ := filepath.Abs(inst.Path)
		instrID := model.ComputeNodeID("InstructionFile", absPath)
		addNode(common.NewNode(instrID, []string{"InstructionFile"}, map[string]any{
			"path":          absPath,
			"type":          inst.Type,
			"hash":          inst.Hash,
			"is_suspicious": inst.IsSuspicious,
		}))

		riskWeight := 0.0
		if inst.IsSuspicious {
			riskWeight = 0.5
		}
		for _, agentID := range agentIDs {
			addEdge(common.NewEdge(agentID, instrID, "LOADS_INSTRUCTIONS", "AgentInstance", "InstructionFile",
				common.NewEdgeProps(scanID, 1.0, riskWeight)))
		}
	}

	return data, nil
}

func (c *ConfigCollector) discoverConfigs(ctx context.Context, opts collector.CollectOptions, homeDir string) ([]ParsedConfig, error) {
	var configs []ParsedConfig

	if opts.Discover {
		for _, p := range c.parsers {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			for _, path := range p.ConfigPaths(homeDir) {
				data, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				cfg, err := p.Parse(path, data)
				if err != nil {
					continue
				}
				configs = append(configs, *cfg)
			}
		}
		return configs, nil
	}

	var paths []string
	if opts.ConfigPath != "" {
		paths = append(paths, opts.ConfigPath)
	}
	paths = append(paths, opts.ConfigPaths...)

	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
		cfg := c.tryParsers(path, data)
		if cfg != nil {
			configs = append(configs, *cfg)
		}
	}

	return configs, nil
}

func (c *ConfigCollector) tryParsers(path string, data []byte) *ParsedConfig {
	for _, p := range c.parsers {
		cfg, err := p.Parse(path, data)
		if err != nil || cfg == nil {
			continue
		}
		if len(cfg.Servers) > 0 {
			return cfg
		}
	}
	return nil
}

func computeServerID(srv ServerDef) string {
	if srv.Transport == "http" {
		return model.ComputeMCPServerID("http", srv.URL)
	}
	sorted := make([]string, len(srv.Args))
	copy(sorted, srv.Args)
	sort.Strings(sorted)
	return model.ComputeMCPServerID("stdio", srv.Command, sorted...)
}

func hostForServer(srv ServerDef) string {
	if srv.Transport == "stdio" {
		return "localhost"
	}
	u, err := url.Parse(srv.URL)
	if err != nil || u.Hostname() == "" {
		return "unknown"
	}
	return u.Hostname()
}

func deriveAuthMethod(env map[string]string, headers map[string]string) string {
	for k, v := range env {
		upper := strings.ToUpper(k)
		if strings.Contains(upper, "OAUTH") || strings.Contains(upper, "CLIENT_ID") {
			return "oauth"
		}
		_ = v
	}
	for k, v := range headers {
		if strings.EqualFold(k, "Authorization") && strings.HasPrefix(v, "Bearer ") {
			return "bearer"
		}
	}
	for k := range env {
		upper := strings.ToUpper(k)
		if strings.Contains(upper, "KEY") || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "SECRET") {
			return "apiKey"
		}
	}
	return "none"
}

func authRiskWeight(method string) float64 {
	switch method {
	case "none":
		return 0.1
	case "apiKey":
		return 0.3
	case "bearer":
		return 0.5
	case "oauth":
		return 0.7
	default:
		return 0.1
	}
}

func identityAuthWeight(identityType string) float64 {
	switch identityType {
	case "none":
		return 0.1
	case "apiKey":
		return 0.3
	case "bearer":
		return 0.5
	case "oauth":
		return 0.7
	default:
		return 0.3
	}
}

func credToIdentityType(cred CredentialInfo) string {
	upper := strings.ToUpper(cred.Name)
	if strings.Contains(upper, "OAUTH") || strings.Contains(upper, "CLIENT_ID") {
		return "oauth"
	}
	if strings.Contains(upper, "BEARER") || cred.Format == "anthropic" || cred.Format == "openai" {
		return "bearer"
	}
	return "apiKey"
}

package config

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"

	"github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
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

// DiscoveryPaths returns the de-duplicated union of every parser's
// ConfigPaths(homeDir). It is the single source of truth for which local
// client config files are scanned during --discover, shared with the MCP
// collector so the two collectors cover identical paths.
func (c *ConfigCollector) DiscoveryPaths(homeDir string) []string {
	var paths []string
	seen := make(map[string]bool)
	for _, p := range c.parsers {
		for _, path := range p.ConfigPaths(homeDir) {
			if path == "" || seen[path] {
				continue
			}
			seen[path] = true
			paths = append(paths, path)
		}
	}
	return paths
}

func (c *ConfigCollector) Collect(ctx context.Context, opts collector.CollectOptions) (*ingest.IngestData, error) {
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
	data.Meta.IdentitySchemes = []ingest.IdentityScheme{{
		EntityKind:   "MCPServer",
		Transport:    "stdio",
		Scheme:       ingest.MCPStdioIdentitySchemeV2,
		Version:      2,
		LegacyScheme: ingest.MCPStdioIdentitySchemeV1,
	}}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	configs, err := c.discoverConfigs(ctx, opts, homeDir)
	if err != nil {
		return nil, err
	}
	coveragePaths, instructionPaths := c.coveragePaths(opts, homeDir)
	data.Meta.Collection = &ingest.CollectionReport{
		State: ingest.OutcomeComplete,
	}
	observedPaths := make(map[string]bool, len(configs))
	for _, cfg := range configs {
		observedPaths[canonicalConfigPath(cfg.Path)] = true
	}
	for _, path := range coveragePaths {
		key := configCoverageKey(path)
		data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, key)
		method := "config_discovery"
		if instructionPaths[canonicalConfigPath(path)] {
			method = "instruction_discovery"
		}
		items := 0
		if observedPaths[canonicalConfigPath(path)] {
			items = 1
		}
		data.Meta.Collection.Outcomes = append(data.Meta.Collection.Outcomes, ingest.CollectionOutcome{
			Collector:   "config",
			CoverageKey: key,
			Target:      canonicalConfigPath(path),
			Method:      method,
			State:       ingest.OutcomeComplete,
			Items:       items,
		})
	}
	sort.Strings(data.Meta.Collection.CoverageKeys)

	nodeIndex := make(map[string]int)
	addNode := func(n ingest.Node, domains ...string) {
		n.ObservationDomains = ingest.MergeObservationDomains(
			n.ObservationDomains,
			domains,
		)
		if index, seen := nodeIndex[n.ID]; seen {
			data.Graph.Nodes[index].ObservationDomains = ingest.MergeObservationDomains(
				data.Graph.Nodes[index].ObservationDomains,
				n.ObservationDomains,
			)
			if data.Graph.Nodes[index].Properties == nil {
				data.Graph.Nodes[index].Properties = make(map[string]any)
			}
			for key, value := range n.Properties {
				data.Graph.Nodes[index].Properties[key] = value
			}
			return
		}
		nodeIndex[n.ID] = len(data.Graph.Nodes)
		data.Graph.Nodes = append(data.Graph.Nodes, n)
	}
	addEdge := func(e ingest.Edge, domains ...string) {
		e.ObservationDomains = ingest.MergeObservationDomains(
			e.ObservationDomains,
			domains,
		)
		data.Graph.Edges = append(data.Graph.Edges, e)
	}

	var agentIDs []string

	for _, cfg := range configs {
		absPath := canonicalConfigPath(cfg.Path)
		scopeKey := configCoverageKey(absPath)
		configFileID := ingest.ComputeNodeID("ConfigFile", absPath)

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
		}), scopeKey)

		agentID := ingest.ComputeNodeID("AgentInstance", configFileID, cfg.Client)
		addNode(common.NewNode(agentID, []string{"AgentInstance"}, map[string]any{
			"name":        cfg.Client,
			"framework":   cfg.Client,
			"config_path": absPath,
		}), scopeKey)
		agentIDs = append(agentIDs, agentID)

		for _, srv := range cfg.Servers {
			if srv.Disabled {
				continue
			}

			serverIdentity := serverIdentityFor(srv)
			serverID := serverIdentity.ObjectID
			endpoint := srv.Command
			if srv.Transport == "http" {
				endpoint = srv.URL
			}

			creds := ExtractCredentials(srv.Env, srv.Headers, srv.Name, opts.IncludeCredentialValues, engine)
			authMethod := deriveAuthMethod(srv.Transport, creds)
			authAssessment := common.AssessAuth(string(authMethod))
			authEvidence := common.AuthEvidenceConfiguredCredential
			if len(creds) == 0 {
				authEvidence = common.AuthEvidenceUnknown
				if srv.Transport == "stdio" {
					authEvidence = common.AuthEvidenceLocalProcess
				}
			}
			pinningStatus := common.PinningNotApplicable
			if srv.Transport == "stdio" {
				pinningStatus = AssessPinning(srv.Command, srv.Args)
			}

			serverProps := map[string]any{
				"name":           srv.Name,
				"endpoint":       endpoint,
				"transport":      srv.Transport,
				"auth_method":    string(authMethod),
				"auth_assurance": string(authAssessment.Assurance),
				"auth_evidence":  authEvidence,
				"pinning_status": string(pinningStatus),
				"id_scheme":      serverIdentity.Scheme,
			}
			if serverIdentity.LegacyObjectID != "" {
				serverProps["legacy_objectid"] = serverIdentity.LegacyObjectID
				serverProps["command"] = srv.Command
				serverProps["args"] = append([]string(nil), srv.Args...)
			}
			switch pinningStatus {
			case common.PinningPinned:
				serverProps["is_pinned"] = true
			case common.PinningUnpinned:
				serverProps["is_pinned"] = false
			}
			addNode(common.NewNode(serverID, []string{"MCPServer"}, serverProps), scopeKey)

			trustWeight := authRiskWeight(string(authMethod))
			trustProps := common.NewEdgeProps(scanID, 1.0, trustWeight)
			trustProps["auth_assessment_complete"] = authAssessment.Weakness != nil
			addEdge(common.NewEdge(agentID, serverID, "TRUSTS_SERVER", "AgentInstance", "MCPServer",
				trustProps), scopeKey)

			addEdge(common.NewEdge(serverID, configFileID, "CONFIGURED_IN", "MCPServer", "ConfigFile",
				common.DefaultEdgeProps(scanID)), scopeKey)

			hostName := hostForServer(srv)
			hostID := common.HostNodeID(hostName)
			hostInfo := common.ClassifyHost(hostName)
			addNode(common.NewNode(hostID, []string{"Host"}, map[string]any{
				"hostname":   hostInfo.Hostname,
				"ip":         hostInfo.IP,
				"scope":      hostInfo.Scope,
				"is_local":   hostInfo.IsLocal,
				"is_private": hostInfo.IsPrivate,
				"is_public":  hostInfo.IsPublic,
			}), scopeKey)
			addEdge(common.NewEdge(serverID, hostID, "RUNS_ON", "MCPServer", "Host",
				common.DefaultEdgeProps(scanID)), scopeKey)

			for _, cred := range creds {
				identityType := credToIdentityType(cred)
				identityID := ingest.ComputeNodeID("Identity", serverID, identityType)
				identityProps := map[string]any{
					"type":           identityType,
					"scope":          srv.Name,
					"is_static":      cred.Type == "hardcoded",
					"auth_assurance": string(common.AssessAuth(identityType).Assurance),
				}
				if serverIdentity.LegacyObjectID != "" {
					identityProps["legacy_objectid"] = ingest.ComputeNodeID(
						"Identity", serverIdentity.LegacyObjectID, identityType)
				}
				addNode(common.NewNode(identityID, []string{"Identity"}, identityProps), scopeKey)

				credID := ingest.ComputeNodeID("Credential", cred.Source, cred.Name)
				// value_hash is the cross-collector merge primitive — see
				// docs/plans/v0.2-implementation.md decision B and
				// sdk/common/hasher.go HashCredentialValue. Always populated
				// from the ORIGINAL raw value (cred.ValueHash carries that;
				// cred.Value may already be the hash when
				// IncludeCredentialValues=false). The credential-chain Cypher
				// in server/internal/analysis/processors/cross_service_credential_chain
				// joins on this property between Config Collector emissions
				// and LiteLLM Looter emissions.
				credProps := map[string]any{
					"type":         cred.Type,
					"name":         cred.Name,
					"source":       cred.Source,
					"is_exposed":   cred.IsExposed,
					"high_entropy": cred.HighEntropy,
					"format":       cred.Format,
					"value_hash":   cred.ValueHash,
					"merge_key":    "value_hash",
				}
				common.ApplyCredentialEvidence(
					credProps,
					cred.IdentityBasis,
					cred.MaterialStatus,
					cred.ExposureStatus,
				)
				// Raw value only when the operator explicitly opts in — the
				// hash above is sufficient for the chain join.
				if opts.IncludeCredentialValues {
					credProps["value"] = cred.Value
				}
				addNode(common.NewNode(credID, []string{"Credential"}, credProps), scopeKey)

				authWeight := identityAuthWeight(identityType)
				addEdge(common.NewEdge(serverID, identityID, "AUTHENTICATES_WITH", "MCPServer", "Identity",
					common.NewEdgeProps(scanID, 1.0, authWeight)), scopeKey)
				addEdge(common.NewEdge(identityID, credID, "USES_CREDENTIAL", "Identity", "Credential",
					common.NewEdgeProps(scanID, 1.0, 0.5)), scopeKey)

				if cred.Type == "hardcoded" || cred.Type == "envVar" {
					addEdge(common.NewEdge(serverID, credID, "HAS_ENV_VAR", "MCPServer", "Credential",
						common.DefaultEdgeProps(scanID)), scopeKey)
				}
			}
		}
	}

	instructions := DiscoverInstructionFiles(homeDir, opts.ProjectDir, engine)
	for _, inst := range instructions {
		absPath := canonicalConfigPath(inst.Path)
		scopeKey := configCoverageKey(absPath)
		instrID := ingest.ComputeNodeID("InstructionFile", absPath)
		addNode(common.NewNode(instrID, []string{"InstructionFile"}, map[string]any{
			"path":          absPath,
			"type":          inst.Type,
			"hash":          inst.Hash,
			"is_suspicious": inst.IsSuspicious,
		}), scopeKey)

		riskWeight := 0.0
		if inst.IsSuspicious {
			riskWeight = 0.5
		}
		for _, agentID := range agentIDs {
			addEdge(common.NewEdge(agentID, instrID, "LOADS_INSTRUCTIONS", "AgentInstance", "InstructionFile",
				common.NewEdgeProps(scanID, 1.0, riskWeight)), scopeKey)
		}
	}

	data.Meta.IdentityAliases = ingest.BuildMCPIdentityAliases(data.Graph.Nodes, true)
	return data, nil
}

func (c *ConfigCollector) coveragePaths(
	opts collector.CollectOptions,
	homeDir string,
) ([]string, map[string]bool) {
	seen := make(map[string]bool)
	instructionPaths := make(map[string]bool)
	var paths []string
	add := func(raw string, instruction bool) {
		path := canonicalConfigPath(raw)
		if path == "" {
			return
		}
		if instruction {
			instructionPaths[path] = true
		}
		if seen[path] {
			return
		}
		seen[path] = true
		paths = append(paths, path)
	}

	if opts.Discover {
		for _, path := range c.DiscoveryPaths(homeDir) {
			add(path, false)
		}
	} else {
		add(opts.ConfigPath, false)
		for _, path := range opts.ConfigPaths {
			add(path, false)
		}
	}
	if homeDir != "" {
		for _, target := range userTargets {
			add(filepath.Join(homeDir, target.relPath), true)
		}
	}
	if opts.ProjectDir != "" {
		for _, target := range projectTargets {
			add(filepath.Join(opts.ProjectDir, target.relPath), true)
		}
	}
	sort.Strings(paths)
	return paths, instructionPaths
}

func canonicalConfigPath(path string) string {
	if path == "" {
		return ""
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Clean(absolute)
}

func configCoverageKey(path string) string {
	return ingest.CanonicalCoverageKey("config", "path", canonicalConfigPath(path))
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

func serverIdentityFor(srv ServerDef) ingest.MCPServerIdentity {
	if srv.Transport == "http" {
		return ingest.ResolveMCPServerIdentity("http", srv.URL)
	}
	return ingest.ResolveMCPServerIdentity("stdio", srv.Command, srv.Args...)
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

// deriveAuthMethod classifies from the exact normalized credential evidence
// that is emitted into the graph. A credential-bearing config therefore cannot
// simultaneously receive auth_method=none.
func deriveAuthMethod(_ string, creds []CredentialInfo) common.AuthMethod {
	if len(creds) == 0 {
		// Configuration alone cannot prove that an endpoint accepts anonymous
		// requests. For stdio, process locality is recorded separately as
		// auth_evidence=local_process.
		return common.AuthUnknown
	}

	priority := map[common.AuthMethod]int{
		common.AuthCustom: 1,
		common.AuthAPIKey: 2,
		common.AuthBasic:  3,
		common.AuthBearer: 4,
		common.AuthOAuth:  5,
		common.AuthOIDC:   6,
		common.AuthMTLS:   7,
	}
	best := common.AuthCustom
	for _, cred := range creds {
		if priority[cred.AuthMethod] > priority[best] {
			best = cred.AuthMethod
		}
	}
	return best
}

func authRiskWeight(method string) float64 {
	return common.AuthTrustWeight(method)
}

func identityAuthWeight(identityType string) float64 {
	return common.AuthTrustWeight(identityType)
}

func credToIdentityType(cred CredentialInfo) string {
	method := cred.AuthMethod
	if method == common.AuthUnknown {
		return string(common.AuthCustom)
	}
	return string(method)
}

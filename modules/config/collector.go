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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	data.Meta.Ruleset = rules.ManifestForEngine(engine)
	data.Meta.IdentitySchemes = []ingest.IdentityScheme{{
		EntityKind: "MCPServer",
		Transport:  "stdio",
		Scheme:     ingest.MCPStdioIdentitySchemeV2,
		Version:    2,
	}}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	projectRoot, err := ResolveProjectRoot(opts.ProjectDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = projectRoot.Close() }()
	paths := append([]string(nil), opts.ConfigPaths...)
	if opts.ConfigPath != "" {
		paths = append([]string{opts.ConfigPath}, paths...)
	}
	discovery := c.DiscoverConfigs(ctx, homeDir, projectRoot, opts.Discover, paths)
	instructions := DiscoverInstructions(ctx, homeDir, projectRoot.Path(), engine)
	if err := projectRoot.Validate(); err != nil {
		discovery.ProjectRootState = ingest.OutcomeFailed
		discovery.ProjectRootError = "project root changed or became unavailable during discovery"
	}
	data.Meta.Collection = &ingest.CollectionReport{}
	projectRootKey := configProjectRootCoverageKey(discovery.ProjectRoot)
	data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, projectRootKey)
	data.Meta.Collection.Outcomes = append(data.Meta.Collection.Outcomes, collectionOutcome(
		projectRootKey, discovery.ProjectRoot, "project_root", discovery.ProjectRootState, 0, discovery.ProjectRootError,
	))
	for _, file := range discovery.Files {
		key := configCoverageKey(file.Path)
		data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, key)
		data.Meta.Collection.Outcomes = append(data.Meta.Collection.Outcomes, collectionOutcome(
			key, file.Path, "config_discovery", file.State, file.Items, file.Error,
		))
	}
	data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, instructions.CoverageKeys...)
	data.Meta.Collection.Outcomes = append(data.Meta.Collection.Outcomes, instructions.Outcomes...)
	data.Meta.Collection.CoverageKeys = uniqueSorted(data.Meta.Collection.CoverageKeys)
	data.Meta.Collection.State = ingest.AggregateOutcomeState(data.Meta.Collection.Outcomes)

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
	edgeIndex := make(map[string]int)
	addEdge := func(e ingest.Edge, domains ...string) {
		e.ObservationDomains = ingest.MergeObservationDomains(
			e.ObservationDomains,
			domains,
		)
		key := e.Kind + "\x00" + e.Source + "\x00" + e.Target
		if index, seen := edgeIndex[key]; seen {
			data.Graph.Edges[index].ObservationDomains = ingest.MergeObservationDomains(
				data.Graph.Edges[index].ObservationDomains,
				e.ObservationDomains,
			)
			return
		}
		edgeIndex[key] = len(data.Graph.Edges)
		data.Graph.Edges = append(data.Graph.Edges, e)
	}

	configs := discovery.ParsedConfigs()
	configsByPath := make(map[string][]ParsedConfig)
	for _, cfg := range configs {
		path := canonicalConfigPath(cfg.Path)
		configsByPath[path] = append(configsByPath[path], cfg)
	}
	configPaths := make([]string, 0, len(configsByPath))
	for path := range configsByPath {
		configPaths = append(configPaths, path)
	}
	sort.Strings(configPaths)
	for _, path := range configPaths {
		views := configsByPath[path]
		clients := make([]string, 0, len(views))
		servers := make(map[string]bool)
		for _, view := range views {
			clients = append(clients, view.Client)
			for _, server := range view.Servers {
				if !server.Disabled {
					servers[serverIdentityFor(server).ObjectID] = true
				}
			}
		}
		clients = uniqueSorted(clients)
		props := map[string]any{
			"path": path, "clients": clients, "server_count": len(servers),
		}
		if len(clients) == 1 {
			props["client"] = clients[0]
		}
		addNode(common.NewNode(ingest.ComputeNodeID("ConfigFile", path), []string{"ConfigFile"}, props), configCoverageKey(path))
	}

	for _, cfg := range configs {
		absPath := canonicalConfigPath(cfg.Path)
		scopeKey := configCoverageKey(absPath)
		configFileID := ingest.ComputeNodeID("ConfigFile", absPath)

		agentID := ingest.ComputeNodeID("AgentInstance", configFileID, cfg.Client)
		addNode(common.NewNode(agentID, []string{"AgentInstance"}, map[string]any{
			"name":        cfg.Client,
			"framework":   cfg.Client,
			"config_path": absPath,
		}), scopeKey)

		for _, srv := range cfg.Servers {
			if srv.Disabled {
				continue
			}

			serverIdentity := serverIdentityFor(srv)
			serverID := serverIdentity.ObjectID
			creds := ExtractCredentials(srv.Env, srv.Headers, srv.Name, opts.IncludeCredentialValues, engine)
			authMethod := deriveAuthMethod(srv.Transport, creds)
			authAssessment := common.AssessAuth(string(authMethod))
			serverProps := serverNodeProperties(srv, creds)
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
				"hostname": hostInfo.Hostname,
				"ip":       hostInfo.IP,
				"scope":    hostInfo.Scope,
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

	for _, observation := range instructions.Observations {
		inst := observation.Info
		absPath := canonicalConfigPath(inst.Path)
		instrID := ingest.ComputeNodeID("InstructionFile", absPath)
		addNode(common.NewNode(instrID, []string{"InstructionFile"}, map[string]any{
			"path":          absPath,
			"type":          inst.Type,
			"hash":          inst.Hash,
			"is_suspicious": inst.IsSuspicious,
		}), observation.OwnerKey)
	}

	return data, nil
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

func configProjectRootCoverageKey(path string) string {
	return ingest.CanonicalCoverageKey("config", "project_root", canonicalConfigPath(path))
}

func serverIdentityFor(srv ServerDef) ingest.MCPServerIdentity {
	if srv.Transport == "http" {
		return ingest.ResolveMCPServerIdentity("http", srv.URL)
	}
	return ingest.ResolveMCPServerIdentity("stdio", srv.Command, srv.Args...)
}

// ServerNodeProperties returns the configuration-backed MCPServer facts shared
// by config collection and MCP auto-discovery. Values are derived without
// retaining raw credential material so the live MCP projection can preserve
// configuration and runtime evidence without semantic last-writer conflicts.
func ServerNodeProperties(srv ServerDef, engine *rules.Engine) map[string]any {
	return serverNodeProperties(
		srv,
		ExtractCredentials(srv.Env, srv.Headers, srv.Name, false, engine),
	)
}

func serverNodeProperties(srv ServerDef, creds []CredentialInfo) map[string]any {
	endpoint := srv.Command
	if srv.Transport == "http" {
		endpoint = srv.URL
	}
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

	props := map[string]any{
		"name":           srv.Name,
		"endpoint":       endpoint,
		"transport":      srv.Transport,
		"auth_method":    string(authMethod),
		"auth_assurance": string(authAssessment.Assurance),
		"auth_evidence":  authEvidence,
		"pinning_status": string(pinningStatus),
		"id_scheme":      serverIdentityFor(srv).Scheme,
	}
	if srv.Transport == "stdio" {
		props["command"] = srv.Command
		props["args"] = append([]string(nil), srv.Args...)
	}
	switch pinningStatus {
	case common.PinningPinned:
		props["is_pinned"] = true
	case common.PinningUnpinned:
		props["is_pinned"] = false
	}
	return props
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

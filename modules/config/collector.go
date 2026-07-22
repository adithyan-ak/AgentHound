package config

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
		Scheme:     ingest.MCPStdioIdentitySchemeV3,
		Version:    3,
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

	nodeSeen := make(map[string]bool)
	addNode := func(n ingest.Node, domains ...string) {
		n.ObservationDomains = ingest.MergeObservationDomains(
			n.ObservationDomains,
			domains,
		)
		if key, comparable := nodeContributionDedupKey(n); comparable && nodeSeen[key] {
			return
		} else if comparable {
			nodeSeen[key] = true
		}
		data.Graph.Nodes = append(data.Graph.Nodes, n)
	}
	edgeSeen := make(map[string]bool)
	addEdge := func(e ingest.Edge, domains ...string) {
		e.ObservationDomains = ingest.MergeObservationDomains(
			e.ObservationDomains,
			domains,
		)
		if key, comparable := edgeContributionDedupKey(e); comparable && edgeSeen[key] {
			return
		} else if comparable {
			edgeSeen[key] = true
		}
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

		for _, group := range groupServerDefinitions(cfg.Servers) {
			srv := group.Definitions[0]
			serverIdentity := group.Identity
			serverID := serverIdentity.ObjectID
			var creds []CredentialInfo
			for _, definition := range group.Definitions {
				creds = append(creds, ExtractServerCredentials(
					definition,
					opts.IncludeCredentialValues,
					engine,
				)...)
			}
			authMethod := deriveAuthMethod(srv.Transport, creds)
			authAssessment := common.AssessAuth(string(authMethod))
			serverProps := serverNodeProperties(srv, creds)
			addNode(common.NewNode(serverID, []string{"MCPServer"}, serverProps), scopeKey)

			trustWeight := authRiskWeight(string(authMethod))
			trustProps := common.NewEdgeProps(scanID, 1.0, trustWeight)
			trustProps["auth_assessment_complete"] = authAssessment.Weakness != nil
			trustProps["configured_names"] = append([]string(nil), group.Names...)
			addEdge(common.NewEdge(agentID, serverID, "TRUSTS_SERVER", "AgentInstance", "MCPServer",
				trustProps), scopeKey)

			configuredProps := common.DefaultEdgeProps(scanID)
			configuredProps["configured_names"] = append([]string(nil), group.Names...)
			addEdge(common.NewEdge(serverID, configFileID, "CONFIGURED_IN", "MCPServer", "ConfigFile",
				configuredProps), scopeKey)

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

			staticIdentityTypes := make(map[string]bool)
			for _, cred := range creds {
				if cred.Type == "hardcoded" {
					staticIdentityTypes[credToIdentityType(cred)] = true
				}
			}
			for _, cred := range creds {
				identityType := credToIdentityType(cred)
				identityID := ingest.ComputeNodeID("Identity", serverID, identityType)
				identityProps := map[string]any{
					"type":           identityType,
					"scope":          serverID,
					"is_static":      staticIdentityTypes[identityType],
					"auth_assurance": string(common.AssessAuth(identityType).Assurance),
				}
				addNode(common.NewNode(identityID, []string{"Identity"}, identityProps), scopeKey)

				credID := ingest.ComputeNodeID(
					"Credential",
					scopeKey,
					serverID,
					cred.Source,
					cred.Location,
					cred.Name,
				)
				// value_hash is the cross-collector merge primitive — see
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
					"location":     cred.Location,
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

				if cred.Location == "env" {
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

type serverDefinitionGroup struct {
	Identity    ingest.MCPServerIdentity
	Names       []string
	Definitions []ServerDef
}

// groupServerDefinitions collapses aliases that refer to the same canonical
// MCP server within one configuration owner. Alias names remain edge-local
// configuration evidence; they must not create conflicting scalar properties
// on the shared MCPServer or Identity nodes.
func groupServerDefinitions(definitions []ServerDef) []serverDefinitionGroup {
	byID := make(map[string]*serverDefinitionGroup)
	for _, definition := range definitions {
		if definition.Disabled {
			continue
		}
		identity := serverIdentityFor(definition)
		group := byID[identity.ObjectID]
		if group == nil {
			group = &serverDefinitionGroup{Identity: identity}
			byID[identity.ObjectID] = group
		}
		group.Names = append(group.Names, definition.Name)
		group.Definitions = append(group.Definitions, definition)
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	groups := make([]serverDefinitionGroup, 0, len(ids))
	for _, id := range ids {
		group := byID[id]
		group.Names = uniqueSorted(group.Names)
		sort.SliceStable(group.Definitions, func(i, j int) bool {
			if group.Definitions[i].Name != group.Definitions[j].Name {
				return group.Definitions[i].Name < group.Definitions[j].Name
			}
			left, leftErr := common.CanonicalJSONHash(group.Definitions[i])
			right, rightErr := common.CanonicalJSONHash(group.Definitions[j])
			if leftErr != nil || rightErr != nil {
				return false
			}
			return left < right
		})
		groups = append(groups, *group)
	}
	return groups
}

// ServerNodeProperties returns the configuration-backed MCPServer facts shared
// by config collection and MCP auto-discovery. Values are derived without
// retaining raw credential material so the live MCP projection can preserve
// configuration and runtime evidence without semantic last-writer conflicts.
func ServerNodeProperties(srv ServerDef, engine *rules.Engine) map[string]any {
	return serverNodeProperties(
		srv,
		ExtractServerCredentials(srv, false, engine),
	)
}

func serverNodeProperties(srv ServerDef, creds []CredentialInfo) map[string]any {
	identity := serverIdentityFor(srv)
	displayName := stdioServerDisplayName(srv.Command, identity.ObjectID)
	var safeHTTP ingest.SanitizedHTTPEndpoint
	if srv.Transport == "http" {
		safeHTTP = ingest.SanitizeHTTPEndpoint(srv.URL)
		displayName = safeHTTP.Display
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
		"name":           displayName,
		"transport":      srv.Transport,
		"auth_method":    string(authMethod),
		"auth_assurance": string(authAssessment.Assurance),
		"auth_evidence":  authEvidence,
		"pinning_status": string(pinningStatus),
		"id_scheme":      identity.Scheme,
	}
	switch srv.Transport {
	case "stdio":
		props["command"] = srv.Command
		props["arg_hashes"] = append([]string{}, identity.ArgumentHashes...)
		props["arg_count"] = len(identity.ArgumentHashes)
	case "http":
		props["endpoint"] = safeHTTP.Display
		if safeHTTP.UserinfoRedacted {
			props["endpoint_userinfo_redacted"] = true
		}
		if safeHTTP.QueryRedacted {
			props["endpoint_query_redacted"] = true
		}
		if safeHTTP.FragmentRedacted {
			props["endpoint_fragment_redacted"] = true
		}
	}
	switch pinningStatus {
	case common.PinningPinned:
		props["is_pinned"] = true
	case common.PinningUnpinned:
		props["is_pinned"] = false
	}
	return props
}

func stdioServerDisplayName(command, objectID string) string {
	name := filepath.Base(strings.TrimSpace(command))
	if name == "." || name == "" {
		name = "stdio"
	}
	digest := strings.TrimPrefix(objectID, "sha256:")
	if len(digest) > 8 {
		digest = digest[:8]
	}
	if digest == "" {
		return name
	}
	return fmt.Sprintf("%s [%s]", name, digest)
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

// Contribution keys deliberately include ownership and semantics. A shared
// graph identity observed by two config scopes must remain two contributions
// until the graph writer fingerprints each owner independently.
func nodeContributionKey(node ingest.Node) string {
	return node.ID + "\x00" + string(node.PropertySemantics) + "\x00" +
		strings.Join(ingest.MergeObservationDomains(node.ObservationDomains), "\x1f")
}

func edgeContributionKey(edge ingest.Edge) string {
	return edge.Source + "\x00" + edge.Kind + "\x00" + edge.Target + "\x00" +
		string(edge.ObservationSemantics) + "\x00" +
		strings.Join(ingest.MergeObservationDomains(edge.ObservationDomains), "\x1f")
}

func nodeContributionDedupKey(node ingest.Node) (string, bool) {
	digest, err := common.CanonicalJSONHash(node)
	return nodeContributionKey(node) + "\x00" + digest, err == nil
}

func edgeContributionDedupKey(edge ingest.Edge) (string, bool) {
	digest, err := common.CanonicalJSONHash(edge)
	return edgeContributionKey(edge) + "\x00" + digest, err == nil
}

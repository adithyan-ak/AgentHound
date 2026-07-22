package mcp

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adithyan-ak/agenthound/modules/config"
	"github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

type MCPCollector struct {
	concurrency int
	timeout     time.Duration
	initTimeout time.Duration
	maxItems    int
	insecure    bool
	engine      *rules.Engine
}

var resolveMCPProjectRoot = config.ResolveProjectRoot

type Option func(*MCPCollector)

func WithConcurrency(n int) Option {
	return func(c *MCPCollector) {
		if n > 0 {
			c.concurrency = n
		}
	}
}

func WithTimeout(d time.Duration) Option {
	return func(c *MCPCollector) {
		if d > 0 {
			c.timeout = d
		}
	}
}

func WithInitTimeout(d time.Duration) Option {
	return func(c *MCPCollector) {
		if d > 0 {
			c.initTimeout = d
		}
	}
}

func WithMaxItems(n int) Option {
	return func(c *MCPCollector) {
		if n > 0 {
			c.maxItems = n
		}
	}
}

func NewMCPCollector(opts ...Option) *MCPCollector {
	c := &MCPCollector{
		concurrency: 5,
		timeout:     120 * time.Second,
		initTimeout: 30 * time.Second,
		maxItems:    defaultMaxItems,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

var _ collector.Collector = (*MCPCollector)(nil)

func (c *MCPCollector) Name() string { return "mcp" }

func (c *MCPCollector) Collect(ctx context.Context, opts collector.CollectOptions) (*ingest.IngestData, error) {
	if opts.Insecure {
		c.insecure = true
	}
	c.engine = opts.RulesEngine
	if c.engine == nil {
		var engineErr error
		c.engine, engineErr = rules.NewEngine(rules.LoadOptions{})
		if engineErr != nil {
			return nil, fmt.Errorf("rules engine: %w", engineErr)
		}
	}

	specs, configDiscovery, err := c.buildServerList(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("build server list: %w", err)
	}
	if len(specs) == 0 && configDiscovery == nil {
		return nil, fmt.Errorf("no MCP servers to enumerate")
	}

	scanID := opts.ScanID
	if scanID == "" {
		scanID = common.GenerateScanID("mcp")
	}

	data := common.NewIngestData("mcp", scanID)
	data.Meta.Ruleset = rules.ManifestForEngine(c.engine)
	data.Meta.IdentitySchemes = []ingest.IdentityScheme{{
		EntityKind: "MCPServer",
		Transport:  "stdio",
		Scheme:     ingest.MCPStdioIdentitySchemeV3,
		Version:    3,
	}}

	results := c.enumerateAll(ctx, specs, scanID)

	nodeSeen := make(map[string]bool)
	addNode := func(node ingest.Node) {
		if key, comparable := mcpNodeContributionDedupKey(node); comparable && nodeSeen[key] {
			return
		} else if comparable {
			nodeSeen[key] = true
		}
		data.Graph.Nodes = append(data.Graph.Nodes, node)
	}
	edgeSeen := make(map[string]bool)
	addEdge := func(edge ingest.Edge) {
		if key, comparable := mcpEdgeContributionDedupKey(edge); comparable && edgeSeen[key] {
			return
		} else if comparable {
			edgeSeen[key] = true
		}
		data.Graph.Edges = append(data.Graph.Edges, edge)
	}
	coverage := make(map[string]bool, len(results))
	report := &ingest.CollectionReport{}
	if configDiscovery != nil {
		rootKey := ingest.CollectorRootCoverageKey("mcp")
		state, items, errorText := summarizeConfigDiscovery(configDiscovery)
		report.CoverageKeys = append(report.CoverageKeys, rootKey)
		report.Outcomes = append(report.Outcomes, ingest.CollectionOutcome{
			Collector: "mcp", CoverageKey: rootKey, Target: "mcp",
			Method: "discover_configs", State: state, Items: items, Error: errorText,
		})
	}
	for _, r := range results {
		if r.Error != nil {
			log.Printf("[mcp] server error: %v", r.Error)
		}
		scopeKey := r.CoverageKey
		if scopeKey == "" {
			scopeKey = ingest.CanonicalCoverageKey("mcp", "target", r.Target)
		}
		coverage[scopeKey] = true
		report.Outcomes = append(report.Outcomes, r.Outcomes...)
		graph := ingest.GraphData{Nodes: r.Nodes, Edges: r.Edges}
		ingest.TagObservationDomain(&graph, scopeKey)
		for _, n := range graph.Nodes {
			addNode(n)
		}
		for _, edge := range graph.Edges {
			addEdge(edge)
		}
	}
	for key := range coverage {
		report.CoverageKeys = append(report.CoverageKeys, key)
	}
	sort.Strings(report.CoverageKeys)
	report.State = ingest.AggregateOutcomeState(report.Outcomes)
	data.Meta.Collection = report

	return data, nil
}

func mcpNodeContributionKey(node ingest.Node) string {
	return node.ID + "\x00" + string(node.PropertySemantics) + "\x00" +
		strings.Join(ingest.MergeObservationDomains(node.ObservationDomains), "\x1f")
}

func mcpEdgeContributionKey(edge ingest.Edge) string {
	return edge.Source + "\x00" + edge.Kind + "\x00" + edge.Target + "\x00" +
		string(edge.ObservationSemantics) + "\x00" +
		strings.Join(ingest.MergeObservationDomains(edge.ObservationDomains), "\x1f")
}

func mcpNodeContributionDedupKey(node ingest.Node) (string, bool) {
	digest, err := common.CanonicalJSONHash(node)
	return mcpNodeContributionKey(node) + "\x00" + digest, err == nil
}

func mcpEdgeContributionDedupKey(edge ingest.Edge) (string, bool) {
	digest, err := common.CanonicalJSONHash(edge)
	return mcpEdgeContributionKey(edge) + "\x00" + digest, err == nil
}

func (c *MCPCollector) enumerateAll(ctx context.Context, specs []ServerSpec, scanID string) []*ServerResult {
	var (
		mu      sync.Mutex
		results []*ServerResult
		wg      sync.WaitGroup
	)

	sem := make(chan struct{}, c.concurrency)

	for _, spec := range specs {
		wg.Add(1)
		go func(s ServerSpec) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			serverCtx, cancel := context.WithTimeout(ctx, c.timeout)
			defer cancel()

			result := c.enumerateServer(serverCtx, s, scanID)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(spec)
	}

	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		return results[i].CoverageKey < results[j].CoverageKey
	})
	return results
}

func (c *MCPCollector) buildServerList(
	ctx context.Context,
	opts collector.CollectOptions,
) ([]ServerSpec, *config.DiscoveryResult, error) {
	var specs []ServerSpec

	if opts.TargetURL != "" {
		specs = append(specs, ServerSpec{
			Name:      opts.TargetURL,
			Transport: "http",
			URL:       opts.TargetURL,
		})
	}

	for _, u := range opts.TargetURLs {
		specs = append(specs, ServerSpec{
			Name:      u,
			Transport: "http",
			URL:       u,
		})
	}

	var discovery *config.DiscoveryResult
	if opts.Discover || opts.ConfigPath != "" || len(opts.ConfigPaths) > 0 {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, nil, fmt.Errorf("get home directory: %w", err)
		}
		projectRoot, err := resolveMCPProjectRoot(opts.ProjectDir)
		if err != nil {
			return nil, nil, err
		}
		defer func() { _ = projectRoot.Close() }()
		paths := append([]string(nil), opts.ConfigPaths...)
		if opts.ConfigPath != "" {
			paths = append([]string{opts.ConfigPath}, paths...)
		}
		discovery = config.NewConfigCollector().DiscoverConfigs(
			ctx, homeDir, projectRoot, opts.Discover, paths,
		)
		for _, parsed := range discovery.ParsedConfigs() {
			for _, server := range parsed.Servers {
				if server.Disabled {
					continue
				}
				specs = append(specs, serverDefToSpec(server))
			}
		}
	}

	return collapseServerSpecs(specs), discovery, nil
}

func serverDefToSpec(server config.ServerDef) ServerSpec {
	return ServerSpec{
		Name: server.Name, ConfiguredNames: []string{server.Name},
		Transport: server.Transport, Command: server.Command,
		Args: append([]string(nil), server.Args...), Env: server.Env, URL: server.URL,
		Headers: server.Headers, Configured: true,
	}
}

const ambiguousServerProfileError = "multiple execution or authentication profiles share one canonical MCP server identity"

// collapseServerSpecs groups aliases by canonical server identity. Identical
// connection profiles are safe aliases and are enumerated once. Profiles that
// differ in command, argv, URL, environment, or headers are not interchangeable
// access paths; choosing one would make map/input order security-significant,
// so the group becomes an explicit fail-closed result with no network attempt.
func collapseServerSpecs(specs []ServerSpec) []ServerSpec {
	type profile struct {
		Transport string            `json:"transport"`
		Command   string            `json:"command"`
		Args      []string          `json:"args"`
		Env       map[string]string `json:"env"`
		URL       string            `json:"url"`
		Headers   map[string]string `json:"headers"`
	}
	type candidate struct {
		spec          ServerSpec
		serverID      string
		profileDigest string
		ambiguous     bool
	}
	candidates := make([]candidate, 0, len(specs))
	for _, spec := range specs {
		canonicalHeaders, conflictingHeaders := canonicalMCPHeaders(spec.Headers)
		spec.Headers = canonicalHeaders
		args := append([]string{}, spec.Args...)
		env := make(map[string]string, len(spec.Env))
		for name, value := range spec.Env {
			env[name] = value
		}
		headers := make(map[string]string, len(spec.Headers))
		for name, value := range spec.Headers {
			headers[name] = value
		}
		digest := ""
		if !conflictingHeaders {
			var err error
			digest, err = common.CanonicalJSONHash(profile{
				Transport: spec.Transport,
				Command:   spec.Command,
				Args:      args,
				Env:       env,
				URL:       spec.URL,
				Headers:   headers,
			})
			if err != nil {
				digest = ""
			}
		}
		candidates = append(candidates, candidate{
			spec: spec, serverID: computeServerID(spec), profileDigest: digest,
			ambiguous: conflictingHeaders,
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].serverID != candidates[j].serverID {
			return candidates[i].serverID < candidates[j].serverID
		}
		if candidates[i].profileDigest != candidates[j].profileDigest {
			return candidates[i].profileDigest < candidates[j].profileDigest
		}
		return candidates[i].spec.Name < candidates[j].spec.Name
	})

	var collapsed []ServerSpec
	for start := 0; start < len(candidates); {
		end := start + 1
		for end < len(candidates) && candidates[end].serverID == candidates[start].serverID {
			end++
		}
		group := candidates[start:end]
		representative := group[0].spec
		profiles := make(map[string]bool)
		ambiguous := false
		var configuredNames []string
		for _, item := range group {
			profiles[item.profileDigest] = true
			ambiguous = ambiguous || item.ambiguous
			if item.spec.Configured {
				representative.Configured = true
				configuredNames = append(configuredNames, item.spec.Name)
				configuredNames = append(configuredNames, item.spec.ConfiguredNames...)
			}
		}
		representative.ConfiguredNames = uniqueSortedStrings(configuredNames)
		if ambiguous || len(profiles) != 1 || group[0].profileDigest == "" {
			representative.Ambiguity = ambiguousServerProfileError
		}
		collapsed = append(collapsed, representative)
		start = end
	}
	return collapsed
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func summarizeConfigDiscovery(result *config.DiscoveryResult) (ingest.OutcomeState, int, string) {
	if result == nil {
		return ingest.OutcomeNotApplicable, 0, ""
	}
	items := 0
	failures := 0
	hasFailed := false
	hasPartial := false
	hasTruncated := false
	switch result.ProjectRootState {
	case ingest.OutcomeFailed:
		hasFailed = true
		failures++
	case ingest.OutcomePartial:
		hasPartial = true
		failures++
	case ingest.OutcomeTruncated:
		hasTruncated = true
		failures++
	}
	for _, file := range result.Files {
		items += file.Items
		if file.State != ingest.OutcomeComplete {
			failures++
		}
		switch file.State {
		case ingest.OutcomeFailed:
			hasFailed = true
		case ingest.OutcomePartial:
			hasPartial = true
		case ingest.OutcomeTruncated:
			hasTruncated = true
		}
	}
	state := ingest.OutcomeComplete
	switch {
	case hasPartial:
		state = ingest.OutcomePartial
	case hasFailed && items > 0:
		state = ingest.OutcomePartial
	case hasFailed:
		state = ingest.OutcomeFailed
	case hasTruncated:
		state = ingest.OutcomeTruncated
	}
	errorText := ""
	if failures > 0 {
		errorText = fmt.Sprintf("%d configuration path(s) incomplete", failures)
	}
	return state, items, errorText
}

func parseConfigForSpecs(path string) ([]ServerSpec, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	root, err := config.ResolveProjectRoot("")
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	discovery := config.NewConfigCollector().DiscoverConfigs(context.Background(), homeDir, root, false, []string{path})
	specs := specsFromDiscovery(discovery)
	// This compatibility helper predates lifecycle-aware collection and cannot
	// return a partial outcome. Preserve usable parsed specs for its callers;
	// production collection consumes DiscoveryResult directly and retains the
	// incomplete state.
	if len(specs) > 0 {
		return specs, nil
	}
	if err := discoveryError(discovery); err != nil {
		return nil, err
	}
	return specs, nil
}

// discoveryCandidatePaths returns the client config paths to scan during
// --discover. It draws from the config collector's parser registry so MCP
// discover and the config collector cover an identical set of paths (Finding
// 18). The shared parser ConfigPaths() are the single source of truth.
func discoveryCandidatePaths(homeDir string) []string {
	root, err := config.ResolveProjectRoot("")
	if err != nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	return config.NewConfigCollector().DiscoveryPathsForRoot(homeDir, root.Path())
}

func discoverAllConfigs() ([]ServerSpec, error) {
	allSpecs, err := discoverRawConfigSpecs()
	if err != nil {
		return nil, err
	}
	return collapseServerSpecs(allSpecs), nil
}

func discoverRawConfigSpecs() ([]ServerSpec, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	root, err := config.ResolveProjectRoot("")
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	discovery := config.NewConfigCollector().DiscoverConfigs(context.Background(), homeDir, root, true, nil)
	if err := discoveryError(discovery); err != nil {
		return nil, err
	}
	return specsFromDiscovery(discovery), nil
}

func specsFromDiscovery(discovery *config.DiscoveryResult) []ServerSpec {
	var specs []ServerSpec
	for _, parsed := range discovery.ParsedConfigs() {
		for _, server := range parsed.Servers {
			if server.Disabled {
				continue
			}
			specs = append(specs, serverDefToSpec(server))
		}
	}
	return specs
}

func discoveryError(discovery *config.DiscoveryResult) error {
	if discovery.ProjectRootState != "" && discovery.ProjectRootState != ingest.OutcomeComplete {
		return fmt.Errorf("project root discovery incomplete: %s", discovery.ProjectRootState)
	}
	for _, file := range discovery.Files {
		if file.State != ingest.OutcomeComplete {
			return fmt.Errorf("configuration discovery incomplete at %s: %s", file.Path, file.State)
		}
	}
	return nil
}

package mcp

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
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
		Scheme:     ingest.MCPStdioIdentitySchemeV2,
		Version:    2,
	}}

	results := c.enumerateAll(ctx, specs, scanID)

	seen := make(map[string]bool)
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
			if !seen[n.ID] {
				seen[n.ID] = true
				data.Graph.Nodes = append(data.Graph.Nodes, n)
				continue
			}
			for i := range data.Graph.Nodes {
				if data.Graph.Nodes[i].ID == n.ID {
					data.Graph.Nodes[i].ObservationDomains = ingest.MergeObservationDomains(
						data.Graph.Nodes[i].ObservationDomains,
						n.ObservationDomains,
					)
					if data.Graph.Nodes[i].Properties == nil {
						data.Graph.Nodes[i].Properties = make(map[string]any)
					}
					for key, value := range n.Properties {
						data.Graph.Nodes[i].Properties[key] = value
					}
					break
				}
			}
		}
		data.Graph.Edges = append(data.Graph.Edges, graph.Edges...)
	}
	for key := range coverage {
		report.CoverageKeys = append(report.CoverageKeys, key)
	}
	sort.Strings(report.CoverageKeys)
	report.State = ingest.AggregateOutcomeState(report.Outcomes)
	data.Meta.Collection = report

	return data, nil
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

	unique := make([]ServerSpec, 0, len(specs))
	seen := make(map[string]bool)
	for _, spec := range specs {
		key := computeServerID(spec)
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, spec)
	}
	return unique, discovery, nil
}

func serverDefToSpec(server config.ServerDef) ServerSpec {
	return ServerSpec{
		Name: server.Name, Transport: server.Transport, Command: server.Command,
		Args: append([]string(nil), server.Args...), Env: server.Env, URL: server.URL,
		Headers: server.Headers, Configured: true,
	}
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

	uniqueSpecs := make([]ServerSpec, 0, len(allSpecs))
	seen := make(map[string]bool)
	for _, spec := range allSpecs {
		key := computeServerID(spec)
		if !seen[key] {
			seen[key] = true
			uniqueSpecs = append(uniqueSpecs, spec)
		}
	}

	return uniqueSpecs, nil
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

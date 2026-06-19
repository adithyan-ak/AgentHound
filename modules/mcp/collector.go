package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/adithyan-ak/agenthound/modules/config"
	"github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
	"gopkg.in/yaml.v3"
)

type MCPCollector struct {
	concurrency int
	timeout     time.Duration
	initTimeout time.Duration
	maxItems    int
	insecure    bool
	engine      *rules.Engine
}

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

	specs, err := c.buildServerList(opts)
	if err != nil {
		return nil, fmt.Errorf("build server list: %w", err)
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("no MCP servers to enumerate")
	}

	scanID := opts.ScanID
	if scanID == "" {
		scanID = common.GenerateScanID("mcp")
	}

	data := common.NewIngestData("mcp", scanID)

	results := c.enumerateAll(ctx, specs, scanID)

	seen := make(map[string]bool)
	for _, r := range results {
		if r.Error != nil {
			log.Printf("[mcp] server error: %v", r.Error)
		}
		for _, n := range r.Nodes {
			if !seen[n.ID] {
				seen[n.ID] = true
				data.Graph.Nodes = append(data.Graph.Nodes, n)
			}
		}
		data.Graph.Edges = append(data.Graph.Edges, r.Edges...)
	}

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
	return results
}

func (c *MCPCollector) buildServerList(opts collector.CollectOptions) ([]ServerSpec, error) {
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

	if opts.ConfigPath != "" {
		parsed, err := parseConfigForSpecs(opts.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("parse config %s: %w", opts.ConfigPath, err)
		}
		specs = append(specs, parsed...)
	}

	for _, p := range opts.ConfigPaths {
		parsed, err := parseConfigForSpecs(p)
		if err != nil {
			log.Printf("[mcp] failed to parse config %s: %v", p, err)
			continue
		}
		specs = append(specs, parsed...)
	}

	if opts.Discover {
		discovered, err := discoverAllConfigs()
		if err != nil {
			return nil, fmt.Errorf("discover configs: %w", err)
		}
		specs = append(specs, discovered...)
	}

	return specs, nil
}

func parseConfigForSpecs(path string) ([]ServerSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if ext := filepath.Ext(path); ext == ".yaml" || ext == ".yml" {
		return parseContinueYAMLForSpecs(path, data)
	}

	var raw map[string]any
	if err := json.Unmarshal(common.StripJSONComments(data), &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON in %s: %w", path, err)
	}

	var specs []ServerSpec
	for _, rootKey := range []string{"mcpServers", "servers"} {
		serversRaw, ok := raw[rootKey]
		if !ok {
			continue
		}
		specs = append(specs, specsFromServerMap(serversRaw)...)
	}

	if serversRaw, ok := raw["mcp.servers"]; ok {
		specs = append(specs, specsFromServerMap(serversRaw)...)
	}
	if mcpRaw, ok := raw["mcp"].(map[string]any); ok {
		if serversRaw, ok := mcpRaw["servers"]; ok {
			specs = append(specs, specsFromServerMap(serversRaw)...)
		}
	}

	if cs, ok := raw["context_servers"].(map[string]any); ok {
		for name, entry := range cs {
			obj, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			settingsRaw, ok := obj["settings"]
			if !ok {
				spec := specFromServerObj(name, obj)
				if spec != nil {
					specs = append(specs, *spec)
				}
				continue
			}
			settings, ok := settingsRaw.(map[string]any)
			if !ok {
				continue
			}
			spec := specFromServerObj(name, settings)
			if spec != nil {
				specs = append(specs, *spec)
			}
		}
	}

	return specs, nil
}

func specsFromServerMap(raw any) []ServerSpec {
	servers, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	var specs []ServerSpec
	for name, entry := range servers {
		obj, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if disabled, ok := obj["disabled"].(bool); ok && disabled {
			continue
		}
		spec := specFromServerObj(name, obj)
		if spec != nil {
			specs = append(specs, *spec)
		}
	}
	return specs
}

func parseContinueYAMLForSpecs(path string, data []byte) ([]ServerSpec, error) {
	var cfg struct {
		MCPServers []struct {
			Name    string            `yaml:"name"`
			Command string            `yaml:"command"`
			Args    []string          `yaml:"args"`
			Env     map[string]string `yaml:"env"`
			URL     string            `yaml:"url"`
			Headers map[string]string `yaml:"headers"`
		} `yaml:"mcpServers"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid YAML in %s: %w", path, err)
	}
	var specs []ServerSpec
	for _, s := range cfg.MCPServers {
		spec := ServerSpec{
			Name:    s.Name,
			Args:    append([]string(nil), s.Args...),
			Env:     s.Env,
			Headers: s.Headers,
		}
		if s.URL != "" {
			spec.Transport = "http"
			spec.URL = s.URL
		} else if s.Command != "" {
			spec.Transport = "stdio"
			spec.Command = s.Command
		} else {
			continue
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func specFromServerObj(name string, obj map[string]any) *ServerSpec {
	spec := &ServerSpec{Name: name}

	for _, urlKey := range []string{"url", "serverUrl"} {
		if u, ok := obj[urlKey].(string); ok && u != "" {
			spec.Transport = "http"
			spec.URL = u
			spec.Env = extractStringMap(obj, "env")
			spec.Headers = extractStringMap(obj, "headers")
			return spec
		}
	}

	if cmd, ok := obj["command"].(string); ok && cmd != "" {
		spec.Transport = "stdio"
		spec.Command = cmd
		if args, ok := obj["args"].([]any); ok {
			for _, a := range args {
				if s, ok := a.(string); ok {
					spec.Args = append(spec.Args, s)
				}
			}
		}
		spec.Env = extractStringMap(obj, "env")
		return spec
	}

	return nil
}

func extractStringMap(obj map[string]any, key string) map[string]string {
	raw, ok := obj[key].(map[string]any)
	if !ok {
		return nil
	}
	m := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			m[k] = s
		}
	}
	return m
}

// discoveryCandidatePaths returns the client config paths to scan during
// --discover. It draws from the config collector's parser registry so MCP
// discover and the config collector cover an identical set of paths (Finding
// 18). The shared parser ConfigPaths() are the single source of truth.
func discoveryCandidatePaths(homeDir string) []string {
	return config.NewConfigCollector().DiscoveryPaths(homeDir)
}

func discoverAllConfigs() ([]ServerSpec, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var allSpecs []ServerSpec
	seen := make(map[string]bool)

	for _, path := range discoveryCandidatePaths(homeDir) {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		specs, err := parseConfigForSpecs(path)
		if err != nil {
			log.Printf("[mcp] failed to parse %s: %v", path, err)
			continue
		}
		for _, s := range specs {
			key := computeServerID(s)
			if !seen[key] {
				seen[key] = true
				allSpecs = append(allSpecs, s)
			}
		}
	}

	return allSpecs, nil
}

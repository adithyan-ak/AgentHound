package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	collector "github.com/adithyan-ak/agenthound/internal/collector"
	"github.com/adithyan-ak/agenthound/internal/model"
	"github.com/adithyan-ak/agenthound/sdk/common"
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

func (c *MCPCollector) Collect(ctx context.Context, opts collector.CollectOptions) (*model.IngestData, error) {
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
		servers, ok := serversRaw.(map[string]any)
		if !ok {
			continue
		}
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

func discoverAllConfigs() ([]ServerSpec, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	candidates := []string{
		homeDir + "/Library/Application Support/Claude/claude_desktop_config.json",
		homeDir + "/.config/claude/claude_desktop_config.json",
		homeDir + "/.claude.json",
		homeDir + "/.cursor/mcp.json",
		homeDir + "/.config/cursor/mcp.json",
		homeDir + "/.codeium/windsurf/mcp_config.json",
		homeDir + "/.cline/mcp_settings.json",
		homeDir + "/.continue/config.json",
	}

	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = homeDir + "/.config"
	}
	candidates = append(candidates,
		xdg+"/Code/User/settings.json",
		xdg+"/Code - Insiders/User/settings.json",
	)

	var allSpecs []ServerSpec
	seen := make(map[string]bool)

	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		specs, err := parseConfigForSpecs(path)
		if err != nil {
			log.Printf("[mcp] failed to parse %s: %v", path, err)
			continue
		}
		for _, s := range specs {
			key := s.Transport + ":" + s.Command + ":" + s.URL
			if !seen[key] {
				seen[key] = true
				allSpecs = append(allSpecs, s)
			}
		}
	}

	return allSpecs, nil
}

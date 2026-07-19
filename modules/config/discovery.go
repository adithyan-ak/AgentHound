package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const maxConfigFileBytes int64 = 4 << 20

var (
	getWorkingDirectory = os.Getwd
	statProjectRoot     = os.Stat
	openProjectRoot     = os.Open
	openConfigFile      = os.Open
)

// FileDiscovery is the collector-neutral result of inspecting one physical
// client configuration file. Configs may contain more than one client view
// when multiple applications legitimately share a settings file.
type FileDiscovery struct {
	Path    string
	Configs []ParsedConfig
	State   ingest.OutcomeState
	Items   int
	Error   string
}

// DiscoveryResult is shared by the config and MCP collectors so both use the
// same paths, parsers, bounds, and failure semantics.
type DiscoveryResult struct {
	ProjectRoot      string
	ProjectRootState ingest.OutcomeState
	ProjectRootError string
	Files            []FileDiscovery
}

// ValidatedProjectRoot keeps the directory identity that was approved as the
// effective project boundary alive until discovery finishes. This prevents a
// removed, renamed, or replaced root from turning project-relative ENOENTs
// into authoritative absence.
type ValidatedProjectRoot struct {
	path string
	dir  *os.File
	info os.FileInfo
}

func (r *ValidatedProjectRoot) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

func (r *ValidatedProjectRoot) Close() error {
	if r == nil || r.dir == nil {
		return nil
	}
	err := r.dir.Close()
	r.dir = nil
	return err
}

// Validate verifies that the project path still resolves to the same readable
// directory whose handle has remained open since ResolveProjectRoot.
func (r *ValidatedProjectRoot) Validate() error {
	if r == nil || r.dir == nil || r.info == nil {
		return errors.New("project root is not open")
	}
	dir, err := openProjectRoot(r.path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	info, err := dir.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() || !os.SameFile(r.info, info) {
		return errors.New("project root identity changed")
	}
	if _, err := dir.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (r *DiscoveryResult) ParsedConfigs() []ParsedConfig {
	if r == nil {
		return nil
	}
	var configs []ParsedConfig
	for _, file := range r.Files {
		configs = append(configs, file.Configs...)
	}
	return configs
}

// ResolveProjectRoot establishes the project boundary used by every local
// collector. An explicitly invalid root is an operator error; it must never be
// treated as an authoritative empty project.
func ResolveProjectRoot(projectDir string) (*ValidatedProjectRoot, error) {
	root := strings.TrimSpace(projectDir)
	if root == "" {
		cwd, err := getWorkingDirectory()
		if err != nil {
			return nil, fmt.Errorf("resolve current project directory: %w", err)
		}
		root = cwd
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve project directory: %w", err)
	}
	abs = filepath.Clean(abs)
	info, err := statProjectRoot(abs)
	if err != nil {
		return nil, fmt.Errorf("access project directory %s: %w", abs, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("project directory %s is not a directory", abs)
	}
	dir, err := openProjectRoot(abs)
	if err != nil {
		return nil, fmt.Errorf("open project directory %s: %w", abs, err)
	}
	openedInfo, err := dir.Stat()
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("inspect project directory %s: %w", abs, err)
	}
	if !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
		_ = dir.Close()
		return nil, fmt.Errorf("project directory %s changed during validation", abs)
	}
	if _, err := dir.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		_ = dir.Close()
		return nil, fmt.Errorf("read project directory %s: %w", abs, err)
	}
	return &ValidatedProjectRoot{path: abs, dir: dir, info: openedInfo}, nil
}

// DiscoveryPathsForRoot returns the de-duplicated physical path inventory for
// exhaustive discovery, rebasing every project-relative parser path onto the
// validated effective project root.
func (c *ConfigCollector) DiscoveryPathsForRoot(homeDir, projectRoot string) []string {
	registry := c.discoveryRegistry(homeDir, projectRoot)
	paths := make([]string, 0, len(registry))
	for path := range registry {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func (c *ConfigCollector) discoveryRegistry(homeDir, projectRoot string) map[string][]ConfigParser {
	registry := make(map[string][]ConfigParser)
	for _, parser := range c.parsers {
		for _, rawPath := range parser.ConfigPaths(homeDir) {
			if rawPath == "" {
				continue
			}
			path := rawPath
			if !filepath.IsAbs(path) {
				path = filepath.Join(projectRoot, path)
			}
			path = canonicalConfigPath(path)
			duplicate := false
			for _, existing := range registry[path] {
				if existing.ClientName() == parser.ClientName() {
					duplicate = true
					break
				}
			}
			if !duplicate {
				registry[path] = append(registry[path], parser)
			}
		}
	}
	for path := range registry {
		sort.Slice(registry[path], func(i, j int) bool {
			return registry[path][i].ClientName() < registry[path][j].ClientName()
		})
	}
	return registry
}

// DiscoverConfigs reads every physical file at most once. Exhaustive mode
// uses the parser path registry; explicitly supplied unknown paths are tested
// against every parser compatible with the file syntax so no valid view is
// silently discarded.
func (c *ConfigCollector) DiscoverConfigs(
	ctx context.Context,
	homeDir string,
	projectRoot *ValidatedProjectRoot,
	discover bool,
	paths []string,
) *DiscoveryResult {
	rootPath := projectRoot.Path()
	result := &DiscoveryResult{
		ProjectRoot: rootPath, ProjectRootState: ingest.OutcomeComplete,
	}
	registry := c.discoveryRegistry(homeDir, rootPath)

	targets := make(map[string][]ConfigParser)
	preferredClients := make(map[string]map[string]bool)
	if discover {
		for path, parsers := range registry {
			targets[path] = parsers
		}
	} else {
		for _, rawPath := range paths {
			path := canonicalConfigPath(rawPath)
			if path == "" {
				continue
			}
			preferredClients[path] = make(map[string]bool)
			for _, parser := range registry[path] {
				preferredClients[path][parser.ClientName()] = true
			}
			// Explicit paths may be copies, exports, or future documented
			// locations, so every syntax-compatible parser gets a chance to
			// inspect the same bounded byte slice. Known path ownership is used
			// only to resolve otherwise indistinguishable client shapes.
			var parsers []ConfigParser
			ext := strings.ToLower(filepath.Ext(path))
			for _, parser := range c.parsers {
				if (ext == ".yaml" || ext == ".yml") != (parser.ClientName() == "continue") {
					continue
				}
				parsers = append(parsers, parser)
			}
			targets[path] = parsers
		}
	}

	ordered := make([]string, 0, len(targets))
	for path := range targets {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	for _, path := range ordered {
		if err := ctx.Err(); err != nil {
			result.Files = append(result.Files, FileDiscovery{
				Path: path, State: ingest.OutcomeFailed, Error: "collection canceled",
			})
			break
		}
		result.Files = append(result.Files, discoverPhysicalFile(path, targets[path], preferredClients[path]))
	}
	if err := projectRoot.Validate(); err != nil {
		result.ProjectRootState = ingest.OutcomeFailed
		result.ProjectRootError = "project root changed or became unavailable during discovery"
	}
	return result
}

func discoverPhysicalFile(path string, parsers []ConfigParser, preferredClients map[string]bool) FileDiscovery {
	file := FileDiscovery{Path: path, State: ingest.OutcomeComplete}
	data, state, errText := readBoundedConfig(path)
	if state != ingest.OutcomeComplete {
		file.State = state
		file.Error = errText
		return file
	}
	if data == nil { // ENOENT is a truthful complete-empty attempt.
		return file
	}

	var parseFailures int
	var parsedViews []ParsedConfig
	for _, parser := range parsers {
		cfg, err := parser.Parse(path, data)
		if err != nil {
			parseFailures++
		}
		if cfg == nil { // Valid file, but this client's shape is absent.
			continue
		}
		cfg.Path = path
		sort.Slice(cfg.Servers, func(i, j int) bool {
			return serverDiscoveryOrder(cfg.Servers[i]) < serverDiscoveryOrder(cfg.Servers[j])
		})
		parsedViews = append(parsedViews, *cfg)
	}
	if preferredClients == nil {
		// Exhaustive registry discovery has physical-path provenance for every
		// parser selected for this file, including genuinely shared settings.
		file.Configs = append(file.Configs, parsedViews...)
	} else if len(preferredClients) > 0 {
		// Explicit files still run every parser, but a documented physical path
		// is stronger client-identity evidence than a shared JSON shape.
		for _, cfg := range parsedViews {
			if preferredClients[cfg.Client] {
				file.Configs = append(file.Configs, cfg)
			}
		}
		if len(file.Configs) == 0 {
			file.Configs = resolveUnclaimedViews(path, parsedViews)
		}
	} else {
		file.Configs = resolveUnclaimedViews(path, parsedViews)
	}
	sort.Slice(file.Configs, func(i, j int) bool {
		return file.Configs[i].Client < file.Configs[j].Client
	})
	if len(file.Configs) > 0 {
		file.Items = 1
	}
	switch {
	case parseFailures > 0 && len(file.Configs) > 0:
		file.State = ingest.OutcomePartial
		file.Error = fmt.Sprintf("%d applicable parser(s) failed", parseFailures)
	case parseFailures > 0:
		file.State = ingest.OutcomeFailed
		file.Error = fmt.Sprintf("%d parser(s) failed", parseFailures)
	}
	return file
}

func resolveUnclaimedViews(path string, parsedViews []ParsedConfig) []ParsedConfig {
	if len(parsedViews) == 0 {
		return nil
	}
	if len(parsedViews) == 1 {
		return []ParsedConfig{parsedViews[0]}
	}
	// Several real clients accept the same top-level mcpServers shape and
	// differ only in optional fields. With no path provenance, choosing one
	// client—or emitting all of them—would fabricate client applicability.
	// Preserve the union of real server definitions under an honest unknown
	// client instead.
	serversByEncoding := make(map[string]ServerDef)
	for _, cfg := range parsedViews {
		for _, server := range cfg.Servers {
			encoded, _ := json.Marshal(server)
			serversByEncoding[string(encoded)] = server
		}
	}
	keys := make([]string, 0, len(serversByEncoding))
	for key := range serversByEncoding {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	servers := make([]ServerDef, 0, len(keys))
	for _, key := range keys {
		servers = append(servers, serversByEncoding[key])
	}
	return []ParsedConfig{{Client: "unknown", Path: path, Servers: servers}}
}

func serverDiscoveryOrder(server ServerDef) string {
	return strings.Join([]string{
		server.Name, server.Transport, server.URL, server.Command, strings.Join(server.Args, "\x00"),
	}, "\x00")
}

func readBoundedConfig(path string) ([]byte, ingest.OutcomeState, string) {
	f, err := openConfigFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ingest.OutcomeComplete, ""
		}
		return nil, ingest.OutcomeFailed, sanitizedFileError(err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigFileBytes+1))
	if err != nil {
		return nil, ingest.OutcomeFailed, sanitizedFileError(err)
	}
	if int64(len(data)) > maxConfigFileBytes {
		return nil, ingest.OutcomeTruncated, fmt.Sprintf("file exceeds %d byte limit", maxConfigFileBytes)
	}
	return data, ingest.OutcomeComplete, ""
}

func sanitizedFileError(err error) string {
	switch {
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "collection canceled"
	default:
		return "file read failed"
	}
}

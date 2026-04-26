package config

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "configs", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func serverByName(servers []ServerDef, name string) *ServerDef {
	for i := range servers {
		if servers[i].Name == name {
			return &servers[i]
		}
	}
	return nil
}

func TestClaudeDesktopParser(t *testing.T) {
	p := &ClaudeDesktopParser{}

	if p.ClientName() != "claude-desktop" {
		t.Fatalf("ClientName = %q, want %q", p.ClientName(), "claude-desktop")
	}

	paths := p.ConfigPaths("/home/user")
	if len(paths) == 0 {
		t.Fatal("ConfigPaths returned empty")
	}

	data := readFixture(t, "claude_desktop.json")
	cfg, err := p.Parse("/fake/path", data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(cfg.Servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(cfg.Servers))
	}

	fs := serverByName(cfg.Servers, "filesystem")
	if fs == nil {
		t.Fatal("server 'filesystem' not found")
	}
	if fs.Transport != "stdio" {
		t.Errorf("filesystem transport = %q, want stdio", fs.Transport)
	}
	if fs.Command != "npx" {
		t.Errorf("filesystem command = %q, want npx", fs.Command)
	}
	if len(fs.Args) != 3 {
		t.Errorf("filesystem args len = %d, want 3", len(fs.Args))
	}
	if fs.Env["NODE_ENV"] != "production" {
		t.Errorf("filesystem env NODE_ENV = %q, want production", fs.Env["NODE_ENV"])
	}

	remote := serverByName(cfg.Servers, "remote-api")
	if remote == nil {
		t.Fatal("server 'remote-api' not found")
	}
	if remote.Transport != "http" {
		t.Errorf("remote-api transport = %q, want http", remote.Transport)
	}
	if remote.URL != "https://mcp.example.com/api" {
		t.Errorf("remote-api URL = %q", remote.URL)
	}
	if remote.Headers["Authorization"] != "Bearer sk-test-12345" {
		t.Errorf("remote-api Authorization header = %q", remote.Headers["Authorization"])
	}
}

func TestClaudeCodeParser(t *testing.T) {
	p := &ClaudeCodeParser{}

	if p.ClientName() != "claude-code" {
		t.Fatalf("ClientName = %q, want %q", p.ClientName(), "claude-code")
	}

	paths := p.ConfigPaths("/home/user")
	if len(paths) != 2 {
		t.Fatalf("ConfigPaths len = %d, want 2; got %v", len(paths), paths)
	}
	if paths[0] != "/home/user/.claude.json" {
		t.Errorf("ConfigPaths[0] = %q, want /home/user/.claude.json", paths[0])
	}
	if paths[1] != ".mcp.json" {
		t.Errorf("ConfigPaths[1] = %q, want .mcp.json", paths[1])
	}

	data := readFixture(t, "claude_code.json")
	cfg, err := p.Parse("/fake/path", data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(cfg.Servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(cfg.Servers))
	}

	pg := serverByName(cfg.Servers, "postgres-dev")
	if pg == nil {
		t.Fatal("server 'postgres-dev' not found")
	}
	if pg.Transport != "stdio" {
		t.Errorf("transport = %q, want stdio", pg.Transport)
	}
	if pg.Env["PGPASSWORD"] != "dev-secret" {
		t.Errorf("PGPASSWORD = %q", pg.Env["PGPASSWORD"])
	}

	slack := serverByName(cfg.Servers, "slack-mcp")
	if slack == nil {
		t.Fatal("server 'slack-mcp' not found")
	}
	if slack.Transport != "http" {
		t.Errorf("transport = %q, want http", slack.Transport)
	}
	if slack.URL != "http://localhost:3001/mcp" {
		t.Errorf("URL = %q", slack.URL)
	}
}

func TestCursorParser(t *testing.T) {
	p := &CursorParser{}

	if p.ClientName() != "cursor" {
		t.Fatalf("ClientName = %q", p.ClientName())
	}

	data := readFixture(t, "cursor.json")
	cfg, err := p.Parse("/fake/path", data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(cfg.Servers) != 3 {
		t.Fatalf("got %d servers, want 3", len(cfg.Servers))
	}

	brave := serverByName(cfg.Servers, "brave-search")
	if brave == nil {
		t.Fatal("server 'brave-search' not found")
	}
	if brave.Disabled {
		t.Error("brave-search should not be disabled")
	}

	github := serverByName(cfg.Servers, "github-mcp")
	if github == nil {
		t.Fatal("server 'github-mcp' not found")
	}
	if !github.Disabled {
		t.Error("github-mcp should be disabled")
	}

	remote := serverByName(cfg.Servers, "remote-cursor")
	if remote == nil {
		t.Fatal("server 'remote-cursor' not found")
	}
	if remote.Transport != "http" {
		t.Errorf("transport = %q, want http", remote.Transport)
	}
}

func TestVSCodeParser(t *testing.T) {
	p := &VSCodeParser{}

	if p.ClientName() != "vscode" {
		t.Fatalf("ClientName = %q", p.ClientName())
	}

	t.Run("nested format", func(t *testing.T) {
		data := readFixture(t, "vscode_settings.json")
		cfg, err := p.Parse("/fake/path", data)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}

		if len(cfg.Servers) != 2 {
			t.Fatalf("got %d servers, want 2", len(cfg.Servers))
		}

		sqlite := serverByName(cfg.Servers, "sqlite")
		if sqlite == nil {
			t.Fatal("server 'sqlite' not found")
		}
		if sqlite.Transport != "stdio" {
			t.Errorf("transport = %q, want stdio", sqlite.Transport)
		}
		if sqlite.Command != "uvx" {
			t.Errorf("command = %q, want uvx", sqlite.Command)
		}

		everything := serverByName(cfg.Servers, "everything")
		if everything == nil {
			t.Fatal("server 'everything' not found")
		}
		if everything.Transport != "http" {
			t.Errorf("transport = %q, want http", everything.Transport)
		}
		if everything.URL != "http://localhost:3002/mcp" {
			t.Errorf("URL = %q", everything.URL)
		}
	})

	t.Run("dotted key format", func(t *testing.T) {
		data := readFixture(t, "vscode_settings_dotted.json")
		cfg, err := p.Parse("/fake/path", data)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}

		if len(cfg.Servers) != 2 {
			t.Fatalf("got %d servers, want 2", len(cfg.Servers))
		}

		puppeteer := serverByName(cfg.Servers, "puppeteer")
		if puppeteer == nil {
			t.Fatal("server 'puppeteer' not found")
		}
		if puppeteer.Command != "npx" {
			t.Errorf("command = %q, want npx", puppeteer.Command)
		}

		sse := serverByName(cfg.Servers, "sse-server")
		if sse == nil {
			t.Fatal("server 'sse-server' not found")
		}
		if sse.URL != "http://localhost:8080/sse" {
			t.Errorf("URL = %q", sse.URL)
		}
	})
}

func TestWindsurfParser(t *testing.T) {
	p := &WindsurfParser{}

	if p.ClientName() != "windsurf" {
		t.Fatalf("ClientName = %q", p.ClientName())
	}

	data := readFixture(t, "windsurf.json")
	cfg, err := p.Parse("/fake/path", data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(cfg.Servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(cfg.Servers))
	}

	mem := serverByName(cfg.Servers, "memory")
	if mem == nil {
		t.Fatal("server 'memory' not found")
	}
	if mem.Transport != "stdio" {
		t.Errorf("transport = %q, want stdio", mem.Transport)
	}

	remote := serverByName(cfg.Servers, "remote-wind")
	if remote == nil {
		t.Fatal("server 'remote-wind' not found")
	}
	if remote.Transport != "http" {
		t.Errorf("transport = %q, want http", remote.Transport)
	}
	if remote.URL != "https://windsurf-mcp.example.com/v1" {
		t.Errorf("URL = %q (serverUrl key should map to URL)", remote.URL)
	}
}

func TestContinueParser(t *testing.T) {
	p := &ContinueParser{}

	if p.ClientName() != "continue" {
		t.Fatalf("ClientName = %q", p.ClientName())
	}

	paths := p.ConfigPaths("/home/user")
	if len(paths) != 1 || paths[0] != "/home/user/.continue/config.yaml" {
		t.Fatalf("ConfigPaths = %v", paths)
	}

	data := readFixture(t, "continue.yaml")
	cfg, err := p.Parse("/fake/path", data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(cfg.Servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(cfg.Servers))
	}

	fs := serverByName(cfg.Servers, "filesystem")
	if fs == nil {
		t.Fatal("server 'filesystem' not found")
	}
	if fs.Transport != "stdio" {
		t.Errorf("transport = %q, want stdio", fs.Transport)
	}
	if fs.Command != "npx" {
		t.Errorf("command = %q, want npx", fs.Command)
	}
	if len(fs.Args) != 3 {
		t.Errorf("args len = %d, want 3", len(fs.Args))
	}
	if fs.Env["NODE_ENV"] != "production" {
		t.Errorf("NODE_ENV = %q", fs.Env["NODE_ENV"])
	}

	http := serverByName(cfg.Servers, "http-tool")
	if http == nil {
		t.Fatal("server 'http-tool' not found")
	}
	if http.Transport != "http" {
		t.Errorf("transport = %q, want http", http.Transport)
	}
	if http.URL != "http://localhost:4000/mcp" {
		t.Errorf("URL = %q", http.URL)
	}
}

func TestZedParser(t *testing.T) {
	p := &ZedParser{}

	if p.ClientName() != "zed" {
		t.Fatalf("ClientName = %q", p.ClientName())
	}

	data := readFixture(t, "zed_settings.json")
	cfg, err := p.Parse("/fake/path", data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(cfg.Servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(cfg.Servers))
	}

	fetch := serverByName(cfg.Servers, "fetch")
	if fetch == nil {
		t.Fatal("server 'fetch' not found")
	}
	if fetch.Transport != "stdio" {
		t.Errorf("transport = %q, want stdio", fetch.Transport)
	}
	if fetch.Command != "npx" {
		t.Errorf("command = %q, want npx", fetch.Command)
	}

	remote := serverByName(cfg.Servers, "remote-zed")
	if remote == nil {
		t.Fatal("server 'remote-zed' not found")
	}
	if remote.Transport != "http" {
		t.Errorf("transport = %q, want http", remote.Transport)
	}
}

func TestClineParser(t *testing.T) {
	p := &ClineParser{}

	if p.ClientName() != "cline" {
		t.Fatalf("ClientName = %q", p.ClientName())
	}

	data := readFixture(t, "cline_mcp_settings.json")
	cfg, err := p.Parse("/fake/path", data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(cfg.Servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(cfg.Servers))
	}

	fs := serverByName(cfg.Servers, "filesystem")
	if fs == nil {
		t.Fatal("server 'filesystem' not found")
	}
	if len(fs.AutoApprove) != 2 {
		t.Fatalf("AutoApprove len = %d, want 2", len(fs.AutoApprove))
	}
	sort.Strings(fs.AutoApprove)
	if fs.AutoApprove[0] != "list_directory" || fs.AutoApprove[1] != "read_file" {
		t.Errorf("AutoApprove = %v", fs.AutoApprove)
	}

	ws := serverByName(cfg.Servers, "web-search")
	if ws == nil {
		t.Fatal("server 'web-search' not found")
	}
	if len(ws.AutoApprove) != 1 || ws.AutoApprove[0] != "search" {
		t.Errorf("web-search AutoApprove = %v", ws.AutoApprove)
	}
	if ws.Transport != "http" {
		t.Errorf("transport = %q, want http", ws.Transport)
	}
}

func TestJetBrainsParser(t *testing.T) {
	p := &JetBrainsParser{}

	if p.ClientName() != "jetbrains" {
		t.Fatalf("ClientName = %q", p.ClientName())
	}

	paths := p.ConfigPaths("/home/user")
	if len(paths) != 2 {
		t.Fatalf("ConfigPaths len = %d, want 2; got %v", len(paths), paths)
	}
	if paths[0] != filepath.Join(".junie", "mcp", "mcp.json") {
		t.Errorf("ConfigPaths[0] = %q, want project-level path", paths[0])
	}
	if paths[1] != filepath.Join("/home/user", ".junie", "mcp", "mcp.json") {
		t.Errorf("ConfigPaths[1] = %q, want user-level path", paths[1])
	}

	data := readFixture(t, "jetbrains.json")
	cfg, err := p.Parse("/fake/path", data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(cfg.Servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(cfg.Servers))
	}

	git := serverByName(cfg.Servers, "git-mcp")
	if git == nil {
		t.Fatal("server 'git-mcp' not found")
	}
	if git.Transport != "stdio" {
		t.Errorf("transport = %q, want stdio", git.Transport)
	}
	if git.Env["GIT_TOKEN"] != "ghp_faketoken" {
		t.Errorf("GIT_TOKEN = %q", git.Env["GIT_TOKEN"])
	}

	remote := serverByName(cfg.Servers, "jb-remote")
	if remote == nil {
		t.Fatal("server 'jb-remote' not found")
	}
	if remote.Transport != "http" {
		t.Errorf("transport = %q, want http", remote.Transport)
	}
}

func TestKiroParser(t *testing.T) {
	p := &KiroParser{}

	if p.ClientName() != "kiro" {
		t.Fatalf("ClientName = %q", p.ClientName())
	}

	data := readFixture(t, "kiro.json")
	cfg, err := p.Parse("/fake/path", data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(cfg.Servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(cfg.Servers))
	}

	aws := serverByName(cfg.Servers, "aws-mcp")
	if aws == nil {
		t.Fatal("server 'aws-mcp' not found")
	}
	if aws.Env["AWS_REGION"] != "us-east-1" {
		t.Errorf("AWS_REGION = %q", aws.Env["AWS_REGION"])
	}
}

func TestAmazonQParser(t *testing.T) {
	p := &AmazonQParser{}

	if p.ClientName() != "amazon-q" {
		t.Fatalf("ClientName = %q", p.ClientName())
	}

	paths := p.ConfigPaths("/home/user")
	if len(paths) != 1 || paths[0] != "/home/user/.aws/amazonq/mcp.json" {
		t.Fatalf("ConfigPaths = %v", paths)
	}

	data := readFixture(t, "amazon_q.json")
	cfg, err := p.Parse("/fake/path", data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(cfg.Servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(cfg.Servers))
	}

	cc := serverByName(cfg.Servers, "codecatalyst")
	if cc == nil {
		t.Fatal("server 'codecatalyst' not found")
	}
	if cc.Transport != "stdio" {
		t.Errorf("transport = %q, want stdio", cc.Transport)
	}
}

func TestAugmentParser(t *testing.T) {
	p := &AugmentParser{}

	if p.ClientName() != "augment" {
		t.Fatalf("ClientName = %q", p.ClientName())
	}

	t.Run("dotted key format", func(t *testing.T) {
		data := readFixture(t, "augment_settings.json")
		cfg, err := p.Parse("/fake/path", data)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}

		if len(cfg.Servers) != 2 {
			t.Fatalf("got %d servers, want 2", len(cfg.Servers))
		}

		ctx := serverByName(cfg.Servers, "augment-context")
		if ctx == nil {
			t.Fatal("server 'augment-context' not found")
		}
		if ctx.Transport != "stdio" {
			t.Errorf("transport = %q, want stdio", ctx.Transport)
		}
		if ctx.Env["AUGMENT_API_KEY"] != "aug_xxxxxxxxxxxx" {
			t.Errorf("AUGMENT_API_KEY = %q", ctx.Env["AUGMENT_API_KEY"])
		}

		remote := serverByName(cfg.Servers, "augment-remote")
		if remote == nil {
			t.Fatal("server 'augment-remote' not found")
		}
		if remote.Transport != "http" {
			t.Errorf("transport = %q, want http", remote.Transport)
		}
	})

	t.Run("nested format", func(t *testing.T) {
		data := readFixture(t, "augment_settings_nested.json")
		cfg, err := p.Parse("/fake/path", data)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}

		if len(cfg.Servers) != 1 {
			t.Fatalf("got %d servers, want 1", len(cfg.Servers))
		}

		nested := serverByName(cfg.Servers, "augment-nested")
		if nested == nil {
			t.Fatal("server 'augment-nested' not found")
		}
		if nested.Command != "node" {
			t.Errorf("command = %q, want node", nested.Command)
		}
	})
}

func TestAllParsersImplementInterface(t *testing.T) {
	parsers := []ConfigParser{
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
	}

	if len(parsers) != 12 {
		t.Fatalf("expected 12 parsers, got %d", len(parsers))
	}

	names := make(map[string]bool)
	for _, p := range parsers {
		name := p.ClientName()
		if names[name] {
			t.Errorf("duplicate ClientName: %q", name)
		}
		names[name] = true

		paths := p.ConfigPaths("/home/testuser")
		if len(paths) == 0 && runtime.GOOS != "windows" {
			t.Errorf("%s: ConfigPaths returned empty on %s", name, runtime.GOOS)
		}
	}
}

func TestParseInvalidJSON(t *testing.T) {
	parsers := []ConfigParser{
		&ClaudeDesktopParser{},
		&ClaudeCodeParser{},
		&CursorParser{},
	}

	for _, p := range parsers {
		_, err := p.Parse("/fake", []byte(`{invalid json`))
		if err == nil {
			t.Errorf("%s: expected error on invalid JSON", p.ClientName())
		}
	}
}

func TestParseEmptyServers(t *testing.T) {
	p := &ClaudeDesktopParser{}
	cfg, err := p.Parse("/fake", []byte(`{}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("got %d servers from empty config, want 0", len(cfg.Servers))
	}
}

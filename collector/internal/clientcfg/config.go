// Package clientcfg holds configuration for the agenthound collector.
//
// The collector is auth-less: it ships JSON over HTTP to an operator-owned
// agenthound-server, or writes JSON to disk for offline pickup. There is no
// API token field; the server is reached on a network the operator already
// controls (localhost, VPN, SSH tunnel).
package clientcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

type Config struct {
	LogLevel    string
	ServerURL   string
	Output      string
	Concurrency int
}

// ClientConfig is the shape persisted to ~/.config/agenthound/config.yaml.
// `setup` writes it; `LoadClientConfig` reads it.
type ClientConfig struct {
	ServerURL string `yaml:"server_url"`
}

// LoadWithFlags creates a Config using flag values → env vars → defaults.
func LoadWithFlags(flags *pflag.FlagSet) *Config {
	cfg := &Config{
		LogLevel:    "info",
		Concurrency: 5,
	}

	cfg.LogLevel = resolve(flags, "log-level", "AGENTHOUND_LOG_LEVEL", cfg.LogLevel)
	cfg.ServerURL = resolve(flags, "server-url", "AGENTHOUND_SERVER_URL", cfg.ServerURL)
	cfg.Output = resolve(flags, "output", "AGENTHOUND_OUTPUT", cfg.Output)

	if v := resolve(flags, "concurrency", "AGENTHOUND_CONCURRENCY", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Concurrency = n
		}
	}

	return cfg
}

// Load creates a Config from env vars and defaults (no flags).
func Load() *Config {
	return LoadWithFlags(nil)
}

// Validate checks that all config values are valid.
func (c *Config) Validate() error {
	var errs []string

	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.LogLevel] {
		errs = append(errs, fmt.Sprintf("invalid log level %q: must be debug/info/warn/error", c.LogLevel))
	}

	if c.Concurrency < 1 {
		errs = append(errs, fmt.Sprintf("invalid concurrency %d: must be >= 1", c.Concurrency))
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ClientConfigPath returns the path to the per-user client config YAML.
func ClientConfigPath() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "agenthound", "config.yaml")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", "agenthound", "config.yaml")
}

// LoadClientConfig resolves the server URL from flags > env > YAML file.
// Returns nil (no error) if no source provides a server URL.
func LoadClientConfig(flags *pflag.FlagSet) (*ClientConfig, error) {
	serverURL := resolve(flags, "server-url", "AGENTHOUND_SERVER_URL", "")

	if serverURL == "" {
		fileCfg, err := loadClientConfigFile()
		if err != nil {
			return nil, fmt.Errorf("reading client config: %w", err)
		}
		if fileCfg != nil {
			serverURL = fileCfg.ServerURL
		}
	}

	if serverURL == "" {
		return nil, nil
	}

	return &ClientConfig{ServerURL: serverURL}, nil
}

func loadClientConfigFile() (*ClientConfig, error) {
	data, err := os.ReadFile(ClientConfigPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", ClientConfigPath(), err)
	}
	return &cfg, nil
}

// SaveClientConfig writes the client config YAML with 0600 permissions.
func SaveClientConfig(cfg *ClientConfig) error {
	path := ClientConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// resolve returns the first non-empty value from: flag, env var, default.
func resolve(flags *pflag.FlagSet, flagName, envName, defaultVal string) string {
	if flags != nil {
		if f := flags.Lookup(flagName); f != nil && f.Changed {
			return f.Value.String()
		}
	}
	if v := os.Getenv(envName); v != "" {
		return v
	}
	return defaultVal
}

// Package servercfg holds configuration for agenthound-server.
//
// Single-user posture: there is no JWT secret, no admin password, no API
// tokens. The server protects itself by binding to 127.0.0.1 by default;
// remote access is the operator's choice (VPN, SSH tunnel, reverse proxy).
package servercfg

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

type Config struct {
	LogLevel      string
	Bind          string
	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword string
	PostgresURI   string
	CORSOrigins   []string
}

// LoadWithFlags creates a Config using flag values → env vars → defaults.
func LoadWithFlags(flags *pflag.FlagSet) *Config {
	cfg := &Config{
		LogLevel:      "info",
		Bind:          "127.0.0.1:8080",
		Neo4jURI:      "bolt://localhost:7687",
		Neo4jUser:     "neo4j",
		Neo4jPassword: "agenthound",
		PostgresURI:   "postgres://agenthound:agenthound@localhost:5432/agenthound?sslmode=disable",
	}

	cfg.LogLevel = resolve(flags, "log-level", "AGENTHOUND_LOG_LEVEL", cfg.LogLevel)
	cfg.Bind = resolve(flags, "bind", "AGENTHOUND_BIND", cfg.Bind)
	cfg.Neo4jURI = resolve(flags, "neo4j-uri", "AGENTHOUND_NEO4J_URI", cfg.Neo4jURI)
	cfg.Neo4jUser = resolve(flags, "neo4j-user", "AGENTHOUND_NEO4J_USER", cfg.Neo4jUser)
	cfg.Neo4jPassword = resolve(flags, "neo4j-password", "AGENTHOUND_NEO4J_PASSWORD", cfg.Neo4jPassword)
	cfg.PostgresURI = resolve(flags, "pg-uri", "AGENTHOUND_PG_URI", cfg.PostgresURI)

	if origins := resolve(flags, "cors-origins", "AGENTHOUND_CORS_ORIGINS", ""); origins != "" {
		for _, o := range strings.Split(origins, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				cfg.CORSOrigins = append(cfg.CORSOrigins, trimmed)
			}
		}
	}
	if len(cfg.CORSOrigins) == 0 {
		// localhost and 127.0.0.1 are distinct origins (RFC 6454 §4).
		// Ship both so the operator can hit either URL without config.
		cfg.CORSOrigins = []string{"http://localhost:8080", "http://127.0.0.1:8080"}
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

	if c.Bind == "" {
		errs = append(errs, "bind address must not be empty")
	} else if _, _, err := net.SplitHostPort(c.Bind); err != nil {
		errs = append(errs, fmt.Sprintf("invalid bind address %q: %v", c.Bind, err))
	}

	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.LogLevel] {
		errs = append(errs, fmt.Sprintf("invalid log level %q: must be debug/info/warn/error", c.LogLevel))
	}

	if c.Neo4jURI == "" {
		errs = append(errs, "neo4j URI must not be empty")
	}
	if c.PostgresURI == "" {
		errs = append(errs, "postgres URI must not be empty")
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation: %s", strings.Join(errs, "; "))
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

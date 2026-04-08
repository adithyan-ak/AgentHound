package config

import (
	"os"
	"strconv"

	"github.com/spf13/pflag"
)

type Config struct {
	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword string
	PostgresURI   string
	APIPort       int
	LogLevel      string
}

// LoadWithFlags creates a Config using flag values → env vars → defaults (in priority order).
func LoadWithFlags(flags *pflag.FlagSet) *Config {
	cfg := &Config{
		Neo4jURI:      "bolt://localhost:7687",
		Neo4jUser:     "neo4j",
		Neo4jPassword: "agenthound",
		PostgresURI:   "postgres://agenthound:agenthound@localhost:5432/agenthound?sslmode=disable",
		APIPort:       8080,
		LogLevel:      "info",
	}

	cfg.Neo4jURI = resolve(flags, "neo4j-uri", "AGENTHOUND_NEO4J_URI", cfg.Neo4jURI)
	cfg.Neo4jUser = resolve(flags, "neo4j-user", "AGENTHOUND_NEO4J_USER", cfg.Neo4jUser)
	cfg.Neo4jPassword = resolve(flags, "neo4j-password", "AGENTHOUND_NEO4J_PASSWORD", cfg.Neo4jPassword)
	cfg.PostgresURI = resolve(flags, "pg-uri", "AGENTHOUND_PG_URI", cfg.PostgresURI)
	cfg.LogLevel = resolve(flags, "log-level", "AGENTHOUND_LOG_LEVEL", cfg.LogLevel)

	if portStr := resolve(flags, "port", "AGENTHOUND_API_PORT", ""); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil {
			cfg.APIPort = port
		}
	}

	return cfg
}

// Load creates a Config from env vars and defaults (no flags).
func Load() *Config {
	return LoadWithFlags(nil)
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

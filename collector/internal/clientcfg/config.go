// Package clientcfg holds configuration for the agenthound collector.
//
// The collector writes one local JSON file and never uploads it. Operators
// move the artifact to their analysis box through their existing channel.
package clientcfg

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

type Config struct {
	LogLevel string
	Output   string
}

// LoadWithFlags creates a Config using flag values → env vars → defaults.
func LoadWithFlags(flags *pflag.FlagSet) *Config {
	cfg := &Config{
		LogLevel: "info",
	}

	cfg.LogLevel = resolve(flags, "log-level", "AGENTHOUND_LOG_LEVEL", cfg.LogLevel)
	cfg.Output = resolve(flags, "output", "AGENTHOUND_OUTPUT", cfg.Output)

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

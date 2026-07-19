// Package clientcfg holds configuration for the agenthound collector.
//
// The collector is auth-less and offline-by-default: it writes JSON to a
// file (or to stdout) and does not phone home. Operators move the scan
// JSON to their analysis box via their existing channel (file copy, SSH,
// C2, or piping into 'agenthound-server ingest -').
package clientcfg

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/spf13/pflag"
)

type Config struct {
	LogLevel       string
	Output         string
	Concurrency    int
	HostID         string
	NetworkRealmID string
}

// LoadWithFlags creates a Config using flag values → env vars → defaults.
func LoadWithFlags(flags *pflag.FlagSet) *Config {
	cfg := &Config{
		LogLevel:    "info",
		Concurrency: 5,
	}

	cfg.LogLevel = resolve(flags, "log-level", "AGENTHOUND_LOG_LEVEL", cfg.LogLevel)
	cfg.Output = resolve(flags, "output", "AGENTHOUND_OUTPUT", cfg.Output)
	cfg.HostID = resolve(flags, "host-id", "AGENTHOUND_HOST_ID", "")
	cfg.NetworkRealmID = resolve(
		flags,
		"network-realm-id",
		"AGENTHOUND_NETWORK_REALM_ID",
		"",
	)

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
	if c.HostID != "" {
		if err := ingest.ValidateOriginID("host_id", c.HostID); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if c.NetworkRealmID != "" {
		if err := ingest.ValidateOriginID("network_realm_id", c.NetworkRealmID); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation: %s", strings.Join(errs, "; "))
	}
	return nil
}

// CollectionOrigin returns the mandatory origin for a command that emits an
// ingest artifact. Non-collection commands may use Config without setting it.
func (c *Config) CollectionOrigin() (ingest.CollectionOrigin, error) {
	if c == nil {
		return ingest.CollectionOrigin{}, fmt.Errorf("collection origin configuration is unavailable")
	}
	origin := ingest.CollectionOrigin{
		HostID:         c.HostID,
		NetworkRealmID: c.NetworkRealmID,
	}
	if err := origin.Validate(); err != nil {
		return ingest.CollectionOrigin{}, fmt.Errorf(
			"collection origin: %w (set --host-id/AGENTHOUND_HOST_ID and --network-realm-id/AGENTHOUND_NETWORK_REALM_ID)",
			err,
		)
	}
	return origin, nil
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

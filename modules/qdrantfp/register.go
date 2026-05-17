package qdrantfp

import (
	"log/slog"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	f, err := New()
	if err != nil {
		slog.Warn("qdrant fingerprinter init failed; service will not be detected", "error", err)
		module.Register(&disabledFingerprinter{})
		return
	}
	module.Register(f)
}

func (*Fingerprinter) ID() string            { return "qdrant.fingerprint" }
func (*Fingerprinter) Action() action.Action { return action.Fingerprint }
func (*Fingerprinter) Target() string        { return "qdrant" }
func (*Fingerprinter) Description() string {
	return "Identify Qdrant vector databases by GET / returning the canonical title + version JSON"
}
func (*Fingerprinter) Version() string     { return "0.4.0-dev" }
func (*Fingerprinter) IsDestructive() bool { return false }

type disabledFingerprinter struct{}

func (*disabledFingerprinter) ID() string            { return "qdrant.fingerprint" }
func (*disabledFingerprinter) Action() action.Action { return action.Fingerprint }
func (*disabledFingerprinter) Target() string        { return "qdrant" }
func (*disabledFingerprinter) Description() string {
	return "Qdrant fingerprinter (disabled — rule failed to load)"
}
func (*disabledFingerprinter) Version() string     { return "0.4.0-dev" }
func (*disabledFingerprinter) IsDestructive() bool { return false }

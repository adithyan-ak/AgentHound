package ollamafp

import (
	"log/slog"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	f, err := New()
	if err != nil {
		slog.Warn("ollama fingerprinter init failed; service will not be detected",
			"error", err)
		module.Register(&disabledFingerprinter{})
		return
	}
	module.Register(f)
}

// Identity methods on the working Fingerprinter.
func (*Fingerprinter) ID() string            { return "ollama.fingerprint" }
func (*Fingerprinter) Action() action.Action { return action.Fingerprint }
func (*Fingerprinter) Target() string        { return "ollama" }
func (*Fingerprinter) Description() string {
	return "Identify Ollama LLM inference servers by GET /api/version"
}
func (*Fingerprinter) Version() string     { return "0.2.0-dev" }
func (*Fingerprinter) IsDestructive() bool { return false }

// disabledFingerprinter is the fallback registered when the rule fails to
// load. It implements the Module interface so registry lookups succeed,
// and its Fingerprint method returns Matched=false unconditionally.
type disabledFingerprinter struct{}

func (*disabledFingerprinter) ID() string            { return "ollama.fingerprint" }
func (*disabledFingerprinter) Action() action.Action { return action.Fingerprint }
func (*disabledFingerprinter) Target() string        { return "ollama" }
func (*disabledFingerprinter) Description() string {
	return "Ollama fingerprinter (disabled — rule failed to load)"
}
func (*disabledFingerprinter) Version() string     { return "0.2.0-dev" }
func (*disabledFingerprinter) IsDestructive() bool { return false }

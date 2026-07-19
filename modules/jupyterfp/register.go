package jupyterfp

import (
	"log/slog"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	f, err := New()
	if err != nil {
		slog.Warn("jupyter fingerprinter init failed; service will not be detected",
			"error", err)
		module.Register(&disabledFingerprinter{})
		return
	}
	module.Register(f)
}

func (*Fingerprinter) ID() string            { return "jupyter.fingerprint" }
func (*Fingerprinter) Action() action.Action { return action.Fingerprint }
func (*Fingerprinter) Target() string        { return "jupyter" }
func (*Fingerprinter) Description() string {
	return "Identify Jupyter Server by public /api evidence plus canonical /api/status success or authentication denial"
}
func (*Fingerprinter) Version() string     { return "0.3.0-dev" }
func (*Fingerprinter) IsDestructive() bool { return false }

type disabledFingerprinter struct{}

func (*disabledFingerprinter) ID() string            { return "jupyter.fingerprint" }
func (*disabledFingerprinter) Action() action.Action { return action.Fingerprint }
func (*disabledFingerprinter) Target() string        { return "jupyter" }
func (*disabledFingerprinter) Description() string {
	return "Jupyter fingerprinter (disabled — rule failed to load)"
}
func (*disabledFingerprinter) Version() string     { return "0.3.0-dev" }
func (*disabledFingerprinter) IsDestructive() bool { return false }

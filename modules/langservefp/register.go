package langservefp

import (
	"log/slog"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	f, err := New()
	if err != nil {
		slog.Warn("langserve fingerprinter init failed; service will not be detected", "error", err)
		module.Register(&disabledFingerprinter{})
		return
	}
	module.Register(f)
}

func (*Fingerprinter) ID() string            { return "langserve.fingerprint" }
func (*Fingerprinter) Action() action.Action { return action.Fingerprint }
func (*Fingerprinter) Target() string        { return "langserve" }
func (*Fingerprinter) Description() string {
	return "Identify LangServe (LangChain HTTP API) by GET /openapi.json containing the LangServe title"
}
func (*Fingerprinter) Version() string     { return "0.4.0-dev" }
func (*Fingerprinter) IsDestructive() bool { return false }

type disabledFingerprinter struct{}

func (*disabledFingerprinter) ID() string            { return "langserve.fingerprint" }
func (*disabledFingerprinter) Action() action.Action { return action.Fingerprint }
func (*disabledFingerprinter) Target() string        { return "langserve" }
func (*disabledFingerprinter) Description() string {
	return "LangServe fingerprinter (disabled — rule failed to load)"
}
func (*disabledFingerprinter) Version() string     { return "0.4.0-dev" }
func (*disabledFingerprinter) IsDestructive() bool { return false }

// Package module — FlagsModule is a sidecar interface for modules that
// need per-module CLI flags. It is a pure side-interface: modules that need
// flags add the method, modules that don't, don't.
//
// Wiring pattern, mirroring how action.Looter / action.Fingerprinter compose
// with module.Module — the registry holds module.Module, callers type-assert
// for capability:
//
//	mod, _ := module.GetByTarget(targetKind, action.Loot)
//	if fm, ok := mod.(module.FlagsModule); ok {
//	    fm.RegisterFlags(cmd.Flags())
//	}
//
// The CLI dispatch helper RegisterFlagsFor below does this in one call so
// the action subcommand (`agenthound loot` etc.) doesn't have to repeat the
// type assertion at every call site.
//
// Why a sidecar instead of widening Module: the vast majority of modules
// ship zero per-module flags. Adding RegisterFlags to the Module interface
// would force every existing module to implement a no-op method. The
// sidecar keeps Module narrow and lets future capability sidecars (e.g.
// StatefulModule for receipt persistence) compose the same way.
package module

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// FlagsModule is implemented by modules that contribute per-module CLI
// flags. The CLI dispatcher type-asserts this against the resolved Module
// and wires the FlagSet at action time.
type FlagsModule interface {
	// RegisterFlags adds the module's flags to the supplied FlagSet. The
	// dispatcher passes a per-command FlagSet so flags from one module do
	// not leak into another module's invocation.
	RegisterFlags(fs *pflag.FlagSet)
}

// RegisterFlagsFor type-asserts m for FlagsModule and registers its flags
// on cmd.Flags(). When m does not implement FlagsModule, this is a no-op.
// Callers do not need to check the assertion themselves.
func RegisterFlagsFor(cmd *cobra.Command, m Module) {
	if cmd == nil || m == nil {
		return
	}
	if fm, ok := m.(FlagsModule); ok {
		fm.RegisterFlags(cmd.Flags())
	}
}

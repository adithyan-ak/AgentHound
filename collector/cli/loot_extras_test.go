package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

// floatFlagModule is a minimal Looter that contributes a single Float64
// per-module flag. It mirrors the real embeddinginvert extractor's
// confidence-threshold flag so the extras path exercises float64 handling
// exactly as a production module would drive it.
type floatFlagModule struct{}

func (*floatFlagModule) ID() string            { return "test.floatflags" }
func (*floatFlagModule) Action() action.Action { return action.Loot }
func (*floatFlagModule) Target() string        { return "test" }
func (*floatFlagModule) Description() string   { return "test module with a float flag" }
func (*floatFlagModule) Version() string       { return "0.0.0" }
func (*floatFlagModule) IsDestructive() bool   { return false }
func (*floatFlagModule) RegisterFlags(fs *pflag.FlagSet) {
	fs.Float64("confidence-threshold", 3.0, "test float flag")
}

// TestCollectModuleExtras_Float64 is a direct regression guard on the
// float64 flag propagation fix: a registered Float64 module flag must
// reach LootOptions.Extras carrying the Go dynamic type float64 (not a
// string), so looters can type-assert extras["flag"].(float64) without a
// parse step.
func TestCollectModuleExtras_Float64(t *testing.T) {
	mod := &floatFlagModule{}

	t.Run("supplied value propagates as float64", func(t *testing.T) {
		cmd := &cobra.Command{Use: "loot"}
		module.RegisterFlagsFor(cmd, mod)
		if err := cmd.ParseFlags([]string{"--confidence-threshold", "2.5"}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}

		extras := collectModuleExtras(cmd, mod)
		raw, ok := extras["confidence-threshold"]
		if !ok {
			t.Fatalf("extras missing confidence-threshold: %v", extras)
		}
		v, ok := raw.(float64)
		if !ok {
			t.Fatalf("confidence-threshold dynamic type = %T, want float64", raw)
		}
		if v != 2.5 {
			t.Errorf("confidence-threshold = %v, want 2.5", v)
		}
	})

	t.Run("default value propagates as float64 when unset", func(t *testing.T) {
		cmd := &cobra.Command{Use: "loot"}
		module.RegisterFlagsFor(cmd, mod)
		if err := cmd.ParseFlags(nil); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}

		extras := collectModuleExtras(cmd, mod)
		v, ok := extras["confidence-threshold"].(float64)
		if !ok {
			t.Fatalf("default confidence-threshold dynamic type = %T, want float64", extras["confidence-threshold"])
		}
		if v != 3.0 {
			t.Errorf("default confidence-threshold = %v, want 3.0", v)
		}
	})

	t.Run("invalid value is rejected at parse time", func(t *testing.T) {
		cmd := &cobra.Command{Use: "loot"}
		module.RegisterFlagsFor(cmd, mod)
		if err := cmd.ParseFlags([]string{"--confidence-threshold", "not-a-float"}); err == nil {
			t.Fatal("ParseFlags accepted a non-float value; want error")
		}
	})
}

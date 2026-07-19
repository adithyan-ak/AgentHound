package action

import (
	"context"
	"errors"
)

var (
	ErrRevertIndeterminate = errors.New("revert indeterminate")
	ErrRevertConflict      = errors.New("revert conflict")
	// ErrRevertPartiallyVerified means the authoritative target state was
	// restored, but a provider-specific secondary observation was unavailable.
	// Callers may treat the recovery write as successful only when the module's
	// contract permits it, and must make the qualification operator-visible.
	ErrRevertPartiallyVerified = errors.New("revert partially verified")
)

// Reverter is the destructive-action super-interface. Every Poisoner and
// Implanter must compose it so each mutation has an explicit recovery path.
// Providers can still reject or prevent recovery at runtime, so callers must
// verify the result rather than treating interface conformance as restoration.
//
// This lives in the SDK from day one because adding it later would be a
// breaking change to every existing destructive-action implementation.
type Reverter interface {
	Revert(ctx context.Context, receipt Receipt) error
}

// Receipt is an empty marker interface. Each destructive action returns a
// concrete receipt type (PoisonReceipt, ImplantReceipt) that satisfies
// Receipt and carries whatever metadata that action needs for recovery.
type Receipt interface{}

// RevertInsecureKey carries the explicit revert-time TLS verification opt-out.
// Credentials are independently resolved from ephemeral environment/config
// sources by the provider adapter and are never stored in the context receipt.
type RevertInsecureKey struct{}

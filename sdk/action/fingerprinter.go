package action

import (
	"context"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// Fingerprinter probes a single Target to identify the running service
// (kind, version, auth posture). Output feeds enumeration and module
// selection downstream.
//
// Implementations also implement sdk/module.Module.
type Fingerprinter interface {
	Fingerprint(ctx context.Context, t Target) (*FingerprintResult, error)
}

// FingerprintResult reports the outcome of a single fingerprinter
// dispatch against a Target. Matched is true only when the probe(s)
// completed successfully and every matcher passed; partial matches
// return Matched=false with no error (a fingerprinter saying "this is
// not my service" is normal, not a system failure).
// A non-nil error means the target was not definitively evaluated (for
// example transport, timeout, redirect, authentication challenge, bounded-body,
// or matcher execution failure) and lifecycle-aware callers must treat the
// corresponding coverage as incomplete.
//
// IngestData carries the nodes and edges the fingerprinter wants merged into
// the scan output. Current service fingerprinters emit a per-service,
// multi-labeled :ServiceKind:AIService node and may emit additional observed
// structure through the same graph payload.
//
// Properties duplicates the IngestData node properties for caller
// convenience (e.g. logging, the scanner's stderr summary). Treat
// IngestData as the canonical source of truth.
type FingerprintResult struct {
	Matched     bool
	ServiceKind string
	Version     string
	AuthMethod  string
	IngestData  *ingest.IngestData
	Properties  map[string]string
}

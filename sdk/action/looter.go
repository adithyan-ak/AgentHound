package action

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// Looter extracts latent secrets, configuration, or state from a Target
// WITHOUT modifying it. Looters are read-only by contract: they MUST
// NOT issue state-mutating requests. GET/HEAD is the norm; PUT, PATCH,
// and DELETE are always prohibited because they change observable target
// state.
//
// Narrow carve-out: a Looter MAY issue a POST when, and only when, the
// target API exposes an idempotent, side-effect-free search/lookup query
// solely via POST (e.g. MLflow's /api/2.0/mlflow/runs/search, Ollama's
// /api/show). Such a POST reads without mutating. Every Looter that uses
// one MUST ship a get_only_test.go regression guard that allowlists the
// specific search/lookup call site (with a justifying comment) and fails
// on any other non-GET method — see modules/ollamaloot/get_only_test.go
// and modules/mlflowloot/get_only_test.go for the pattern. This keeps the
// contract, the code, and the operator-facing CLI claims in agreement.
//
// See docs/plans/sprint3-offensive-primitives.md 4.7 for the full
// Reverter contract discussion.
//
// Implementations also implement sdk/module.Module.
type Looter interface {
	Loot(ctx context.Context, t Target, opts LootOptions) (*LootResult, error)
}

// LootOptions configures a single loot dispatch. Credentials supplies
// operator-known secrets keyed by name (e.g. "master_key" → "sk-..."),
// MaxItems caps emitted nodes per category (per-provider Credentials,
// virtual-keys, etc.), Timeout caps total wallclock for the dispatch,
// and IncludeCredentialValues controls whether raw secret values are
// stored on emitted nodes (vs. hashed).
//
// Looter implementations should read Credentials defensively — missing
// keys produce an error, not a panic. The CLI layer normalizes
// per-module flags (e.g. --master-key) into Credentials["master_key"].
type LootOptions struct {
	Credentials             map[string]string
	MaxItems                int
	Timeout                 time.Duration
	IncludeCredentialValues bool

	// EngagementID is recorded on every emitted edge's evidence map and
	// surfaces in the Looter's slog output, so the operator's IR
	// notification has a stable correlation key. See section 9.5 of
	// docs/plans/sprint3-offensive-primitives.md.
	EngagementID string

	// Extras carries per-Looter flag values populated by the CLI dispatch
	// from the Looter's FlagsModule.RegisterFlags surface. Keys are the
	// per-module flag names (e.g. "include-embeddings", "master-key") so
	// each Looter can pull its own without colliding with another's. The
	// Ollama Looter reads Extras["include-embeddings"] (bool); the Open
	// WebUI Looter reads Extras["api-key"] (string); LiteLLM reads its
	// master-key sugar the same way.
	//
	// Generic LootOptions stays free of per-Looter fields; new Looters
	// should add their flags to RegisterFlags and read them from Extras
	// rather than widening this struct.
	Extras map[string]any
}

// LootResult carries the ingest payload (multi-label nodes + edges)
// produced by a successful loot dispatch, plus diagnostic state that
// helps the operator understand partial outcomes.
//
// PartialErrors is non-empty when individual subprobes failed (e.g.
// /key/list returned 401) but other subprobes succeeded — the looter
// returns useful results AND the failure list, rather than aborting.
//
// Summary is populated for the CLI's stderr summary line; treat
// IngestData as the canonical source for graph state.
type LootResult struct {
	IngestData    *ingest.IngestData
	PartialErrors []string
	Summary       LootSummary
}

// LootSummary is what the CLI prints after a loot dispatch.
type LootSummary struct {
	EndpointsProbed  int
	CredentialsFound int
	PartialFailures  int
}

// ToIngest returns the ingest payload that should be appended to the
// scan envelope. Returns the zero IngestData when the loot did not
// match (so callers can blindly append without nil-checking).
func (r *LootResult) ToIngest() *ingest.IngestData {
	if r == nil || r.IngestData == nil {
		return &ingest.IngestData{}
	}
	return r.IngestData
}

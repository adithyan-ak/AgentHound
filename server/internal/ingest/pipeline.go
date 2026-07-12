package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

// nodeEdgeWriter is the subset of *graph.Writer that Pipeline needs.
// Defining it as an interface lets tests substitute a recording mock.
// *graph.Writer satisfies it implicitly.
type nodeEdgeWriter interface {
	WriteNodesForGeneration(ctx context.Context, nodes []sdkingest.Node, scanID, generationID string) (int, error)
	WriteEdgesForGeneration(ctx context.Context, edges []sdkingest.Edge, scanID, generationID string) (int, error)
}

// scanRecorder is the subset of *appdb.ScanStore that Pipeline needs.
// *appdb.ScanStore satisfies it implicitly.
type scanRecorder interface {
	CreateScan(ctx context.Context, scan *model.Scan) error
	UpdateScan(ctx context.Context, id, status string, nodeCount, edgeCount int, scanErr string) error
	// RecordGenerationOutcome persists the generation-scoped truth columns
	// (coverage, per-stage states, inventory deltas) without flipping the
	// current pointer.
	RecordGenerationOutcome(ctx context.Context, scan *model.Scan) error
	// CurrentScanForScope returns the promoted scan for a collector scope
	// (nil when none), used for coverage-aware retention and demotion.
	CurrentScanForScope(ctx context.Context, collector string) (*model.Scan, error)
	// PromoteGeneration flips the current pointer to scanID for its scope.
	PromoteGeneration(ctx context.Context, scanID, collector string) error
	// CurrentGenerations returns every promoted generation across scopes. Used
	// to select the current collector generations the cross-service credential
	// chain joins across (config generation + loot generation).
	CurrentGenerations(ctx context.Context) ([]model.Scan, error)
}

// postProcessFunc runs the analysis post-processors. Defaulted to
// analysis.RunPostProcessors; replaceable in tests to assert behavior
// without exercising every concrete processor.
type postProcessFunc func(ctx context.Context, db graph.GraphDB, scanID string, collectors []string) ([]graph.ProcessingStats, error)

// findingSnapshotter persists the per-scan findings snapshot to Postgres.
// *appdb.FindingStore satisfies it implicitly; defined as an interface so
// tests can substitute a recorder and so a nil store cleanly disables the
// snapshot stage.
type findingSnapshotter interface {
	InsertFindings(ctx context.Context, scanID string, findings []model.Finding) error
}

// Pipeline serializes ingests through a single mutex.
//
// The post-processing stage's stale-edge cleanup deletes composite
// edges where scan_id != current AND source_collector IN current. Two
// concurrent mcp ingests would both run that DELETE, each treating the
// other's freshly-written edges as stale, producing edge-flapping or
// duplicate work. For a single-user server, serializing ingests is the
// correct trade-off: ingest is rare (operator-driven), the lock holds
// for the duration of a single scan, and concurrent UI uploads are not
// a target scenario.
//
// Generation model: each ingest run is one generation (a UUID). Nodes and
// edges it writes are tagged with that generation_id; the generation only
// becomes the default read target (is_current) after the required stages
// succeed (promotion). A partial or failed generation records honest
// per-stage state and inventory deltas but is never promoted, so default
// reads scoped to current generations never surface staged partial facts.
type Pipeline struct {
	coord        *Coordinator
	validator    *Validator
	normalizer   *Normalizer
	writer       nodeEdgeWriter
	graphDB      graph.GraphDB
	scanStore    scanRecorder
	findingStore findingSnapshotter
	runPP        postProcessFunc
}

// Coordinator serializes graph-mutating operations against one another. Ingest
// and scan deletion both mutate the shared Neo4j graph; a delete's
// generation-GC (which prunes facts whose generations set became empty) must
// never run concurrently with an ingest that has written facts but not yet
// tagged them (they carry an empty generations set until stage 6.4), or the GC
// would treat those in-flight facts as orphans and delete them. A single
// process-wide Coordinator, shared by the Pipeline and the scan-delete handler,
// makes ingest and delete mutually exclusive. For a single-user, localhost
// server these operations are rare and operator-driven, so serializing them is
// the correct, simple trade-off.
type Coordinator struct{ mu sync.Mutex }

// NewCoordinator returns a ready-to-share Coordinator.
func NewCoordinator() *Coordinator { return &Coordinator{} }

// Lock/Unlock guard a graph-mutating critical section.
func (c *Coordinator) Lock()   { c.mu.Lock() }
func (c *Coordinator) Unlock() { c.mu.Unlock() }

// Coordinator exposes the pipeline's shared coordinator so the scan-delete
// handler can serialize against ingest through the same lock.
func (p *Pipeline) Coordinator() *Coordinator { return p.coord }

func NewPipeline(writer *graph.Writer, graphDB graph.GraphDB, scanStore *appdb.ScanStore, findingStore *appdb.FindingStore) *Pipeline {
	p := &Pipeline{
		coord:      NewCoordinator(),
		validator:  NewValidator(),
		normalizer: NewNormalizer(),
		graphDB:    graphDB,
		runPP:      analysis.RunPostProcessors,
	}
	// Avoid the typed-nil-into-interface trap: assign only if the
	// concrete pointer is non-nil so `p.writer != nil` checks behave
	// the same as before the interface seam was introduced.
	if writer != nil {
		p.writer = writer
	}
	if scanStore != nil {
		p.scanStore = scanStore
	}
	if findingStore != nil {
		p.findingStore = findingStore
	}
	return p
}

func (p *Pipeline) Ingest(ctx context.Context, data *sdkingest.IngestData) (*sdkingest.IngestResult, error) {
	// Serialize ingests against each other AND against scan deletion through
	// the shared coordinator (see Coordinator doc-comment). Nil-guarded so a
	// test-constructed Pipeline literal without a coordinator still runs.
	if p.coord != nil {
		p.coord.Lock()
		defer p.coord.Unlock()
	}

	start := time.Now()
	generationID := newGenerationID()
	scope := collectorScope(data.Meta)
	coverageStatus := coverageStatusFor(data.Meta)

	result := &sdkingest.IngestResult{
		ScanID:       data.Meta.ScanID,
		GenerationID: generationID,
	}
	// stages tracks each ingest stage's independent outcome so a failure in
	// one is never masked by success in another (no more 0/0 success-like
	// history).
	stages := newStageTracker()

	// Stage 1: Validate (before any scan record — a rejected artifact must
	// not leave a phantom scan row).
	if err := p.validator.Validate(data); err != nil {
		return nil, err
	}
	slog.Info("validation passed", "nodes", len(data.Graph.Nodes), "edges", len(data.Graph.Edges))

	// Stage 2: Normalize
	warnings := p.normalizer.Normalize(data)
	result.Warnings = warnings
	if len(warnings) > 0 {
		slog.Info("normalization warnings", "count", len(warnings))
	}

	capturedAt := parseCaptureTime(data.Meta.Timestamp)

	// Stamp provenance (source collector + capture time) onto every raw
	// node/edge observation so the read-side logical projection can resolve
	// property conflicts by a deterministic, MEANINGFUL precedence (collector
	// authority, then capture/completion time) instead of a random-UUID
	// generation_id. See server/internal/graph/reader_projection.go.
	stampProvenance(data)

	// Stage 3: Record scan start with generation identity + coverage manifest.
	if p.scanStore != nil {
		scan := &model.Scan{
			ID:              data.Meta.ScanID,
			Collector:       data.Meta.Collector,
			Scope:           scope,
			Status:          model.ScanStatusRunning,
			StartedAt:       time.Now().UTC(),
			GenerationID:    generationID,
			SchemaVersion:   schemaVersionOf(data.Meta),
			IdentityVersion: identityVersionOf(data.Meta),
			CoverageStatus:  coverageStatus,
			Coverage:        data.Meta.Coverage,
			CapturedAt:      capturedAt,
		}
		if err := p.scanStore.CreateScan(ctx, scan); err != nil {
			slog.Warn("failed to create scan record", "error", err)
		}
	}

	// Look up the prior current generation for this scope before we mutate
	// the graph, so retention and demotion target the right predecessor.
	var priorCurrent *model.Scan
	if p.scanStore != nil {
		pc, err := p.scanStore.CurrentScanForScope(ctx, scope)
		if err != nil {
			slog.Warn("current-generation lookup failed", "scope", scope, "error", err)
		}
		priorCurrent = pc
	}

	// Inventory pre-counts (before writes). Non-fatal: a failed count leaves
	// the delta zeroed rather than aborting a real ingest. BeforeTotal is the
	// prior generation's current-view size for this scope (0 when there is no
	// prior current generation): because retention is non-destructive, the
	// whole-graph count would include demoted generations, so a generation-
	// scoped count is the truthful "before" for this scope's promoted view.
	nodeInv := &sdkingest.InventoryDelta{}
	edgeInv := &sdkingest.InventoryDelta{}
	var existingNodes int
	priorGen := ""
	if priorCurrent != nil {
		priorGen = priorCurrent.GenerationID
	}
	if p.graphDB != nil {
		if priorGen != "" {
			nodeInv.BeforeTotal = p.count(ctx, cypherCountNodesInGen, map[string]any{"gen": priorGen})
			// Edge before-total is the prior current generation's distinct
			// logical triple count (F6).
			edgeInv.BeforeTotal = p.count(ctx, cypherCountEdgeTriplesInGen, map[string]any{"gen": priorGen})
		}
		if n, err := countExistingNodes(ctx, p.graphDB, data.Graph.Nodes); err != nil {
			slog.Warn("existing-node count failed", "error", err)
		} else {
			existingNodes = n
		}
	}

	// Stage 4: Write nodes
	nodesWritten, err := p.writer.WriteNodesForGeneration(ctx, data.Graph.Nodes, data.Meta.ScanID, generationID)
	if err != nil {
		stages.set(sdkingest.StageWrite, sdkingest.StageFailed, err)
		p.failGeneration(ctx, data.Meta, generationID, coverageStatus, capturedAt, nodesWritten, 0, stages, err)
		return nil, fmt.Errorf("write nodes: %w", err)
	}
	result.NodesWritten = nodesWritten
	slog.Info("nodes written", "count", nodesWritten)

	// Stage 5: Write edges
	edgesWritten, err := p.writer.WriteEdgesForGeneration(ctx, data.Graph.Edges, data.Meta.ScanID, generationID)
	if err != nil {
		// Nodes committed, edges did not: a partial write. Record it as
		// such (with the real node count) instead of hiding it behind 0/0.
		stages.set(sdkingest.StageWrite, sdkingest.StagePartial, err)
		p.failGeneration(ctx, data.Meta, generationID, coverageStatus, capturedAt, nodesWritten, 0, stages, err)
		return nil, fmt.Errorf("write edges: %w", err)
	}
	result.EdgesWritten = edgesWritten
	stages.set(sdkingest.StageWrite, sdkingest.StageSucceeded, nil)
	slog.Info("edges written", "count", edgesWritten)

	// Accurate node/edge inventory. Created = incoming ids not previously
	// present; Updated = incoming ids that were re-observed. Unchanged stays
	// 0: every MERGE ON MATCH rewrites last_seen/scan_id, so we cannot honestly
	// claim a re-observed fact was byte-identical without a stored content
	// hash — undercounting "unchanged" is the truthful conservative choice.
	nodeInv.Created = clampNonNeg(len(distinctNodeIDs(data.Graph.Nodes)) - existingNodes)
	nodeInv.Updated = existingNodes
	// Edge Created/Updated/After are computed after generation tagging (below)
	// as DISTINCT logical triples diffed against the prior current generation
	// (F6), so they are not derived here from the raw incoming edge list.

	// Stage 6: Post-processing (non-fatal)
	var ppErr error
	if p.graphDB != nil && p.runPP != nil {
		var ppStats []graph.ProcessingStats
		ppStats, ppErr = p.runPP(ctx, p.graphDB, data.Meta.ScanID, []string{data.Meta.Collector})
		if ppErr != nil {
			slog.Error("post-processing failed", "error", ppErr)
			stages.set(sdkingest.StagePostProcessing, sdkingest.StageFailed, ppErr)
		} else {
			stages.set(sdkingest.StagePostProcessing, sdkingest.StageSucceeded, nil)
		}
		for _, s := range ppStats {
			result.PostProcessingStats = append(result.PostProcessingStats, sdkingest.PostProcessingStat{
				ProcessorName: s.ProcessorName,
				EdgesCreated:  s.EdgesCreated,
				NodesUpdated:  s.NodesUpdated,
				Duration:      s.Duration,
				Error:         s.Error,
			})
		}
	} else {
		stages.set(sdkingest.StagePostProcessing, sdkingest.StageSkipped, nil)
	}

	// Stage 6.4: Tag this generation. Runs after post-processing so the
	// composite edges the processors just wrote are stamped too. Tagging
	// failure degrades the write stage to partial but does not roll back the
	// committed facts.
	if p.graphDB != nil {
		if err := tagGeneration(ctx, p.graphDB, data.Meta.ScanID, generationID); err != nil {
			slog.Warn("generation tagging failed", "error", err)
			stages.set(sdkingest.StageWrite, sdkingest.StagePartial, err)
		}
	}

	// Stage 6.5: Cross-generation credential chain. The Config Collector and a
	// Looter ship as separate artifacts (separate generations), so the
	// single-scan processor never joined them. Re-run the join across the
	// EXPLICITLY selected current collector generations plus this one, keyed by
	// generations-set membership, so a config generation's env-var Credential
	// and a loot generation's LiteLLM master key merge by value_hash. The OWNER
	// generation itself is gated to eligible chain anchors (config-bearing with
	// explicit coverage, or a complete/partial loot) so an mcp/a2a/network
	// re-ingest, or a failed/unknown-coverage artifact, never runs the chain and
	// re-attributes edges to a generation that makes no positive chain claim.
	// Non-fatal to already-committed writes, but selection/chain errors fail the
	// post-processing stage so the promotion gate blocks the generation.
	if p.graphDB != nil && ownerEligibleForCredentialChain(scope, data.Meta.Collector, coverageStatus) {
		// Owner-specific, immutable selection: join across the CURRENT
		// generations of OTHER scopes that are eligible chain participants
		// (complete/partial loot generations, or config-bearing generations with
		// EXPLICIT coverage), plus this owner generation. Excluding the owner's
		// own scope drops a superseded same-scope generation so the chain never
		// mixes a demoted prior loot/config generation with the new one; the
		// coverage gate stops an unknown/failed-coverage artifact from asserting
		// a chain. Emitted edges are attributed to (and scoped by) this owner
		// generation, and the join requires the owner to contribute an actually
		// matched observation.
		gens, selErr := p.selectCredentialChainGenerations(ctx, scope)
		if selErr != nil {
			// The current-generation selection could not be read, so the chain
			// would be computed against an unknown/incomplete generation set and
			// understate reachability. Fail post-processing so the promotion gate
			// blocks it — a generation whose chain could not be selected must
			// never become current.
			slog.Error("cross-generation credential chain selection failed", "error", selErr)
			stages.set(sdkingest.StagePostProcessing, sdkingest.StageFailed, selErr)
			if ppErr == nil {
				ppErr = selErr
			}
		} else {
			gens = appendUnique(gens, generationID)
			if written, cerr := analysis.CrossGenerationCredentialChain(ctx, p.graphDB, gens, generationID, data.Meta.ScanID); cerr != nil {
				// A failed chain means this generation's credential-chain findings
				// are missing/incomplete, so the promoted view would understate
				// reachability. Fail post-processing so the promotion gate blocks
				// it — a broken chain must never become current.
				slog.Error("cross-generation credential chain failed", "error", cerr)
				stages.set(sdkingest.StagePostProcessing, sdkingest.StageFailed, cerr)
				if ppErr == nil {
					ppErr = cerr
				}
			} else if written > 0 {
				slog.Info("cross-generation credential chain edges", "count", written,
					"generation_id", generationID, "selected_generations", len(gens))
			}
		}
	}

	// Stage 6.6: Coverage-aware retention (non-destructive). Prior facts are
	// only "retired" when this generation's coverage is complete — a partial/
	// failed/unknown artifact makes no claim about absence, so the predecessor's
	// observations are retained and its posture stays visible. Even for a
	// complete generation, retirement does NOT delete: an absent prior fact
	// loses currency via demotion (default reads scope to the promoted
	// generations' sets) but survives so a later delete of this generation can
	// rematerialize the prior one. We only count the retired facts here.
	if p.graphDB != nil && coverageStatus.IsClean() && priorCurrent != nil &&
		priorCurrent.GenerationID != "" && priorCurrent.GenerationID != generationID {
		nr, _, rerr := countRetiredGeneration(ctx, p.graphDB, priorCurrent.GenerationID, generationID)
		if rerr != nil {
			slog.Warn("generation retention count failed", "prior_generation", priorCurrent.GenerationID, "error", rerr)
		} else {
			nodeInv.Retired = nr
			if nr > 0 {
				slog.Info("retired prior-generation nodes (non-destructive)", "nodes", nr, "prior_generation", priorCurrent.GenerationID)
			}
		}
	}

	// After-totals reflect this generation's current view (facts it observed),
	// consistent with the generation-scoped BeforeTotal above. Edge inventory
	// is computed as DISTINCT logical (source, kind, target) triples diffed
	// against the prior current generation (F6): kept = triples in both,
	// created = after - kept, updated = kept, retired = before - kept (only for
	// a coverage-complete generation, which is the only kind that makes an
	// absence claim).
	if p.graphDB != nil {
		nodeInv.AfterTotal = p.count(ctx, cypherCountNodesInGen, map[string]any{"gen": generationID})
		edgeInv.AfterTotal = p.count(ctx, cypherCountEdgeTriplesInGen, map[string]any{"gen": generationID})
		kept := 0
		if priorGen != "" && priorGen != generationID {
			kept = p.count(ctx, cypherKeptEdgeTriples, map[string]any{"gen": generationID, "prior": priorGen})
		}
		edgeInv.Updated = kept
		edgeInv.Created = clampNonNeg(edgeInv.AfterTotal - kept)
		if coverageStatus.IsClean() && priorGen != "" && priorGen != generationID {
			edgeInv.Retired = clampNonNeg(edgeInv.BeforeTotal - kept)
		}
	}
	result.NodeInventory = nodeInv
	result.EdgeInventory = edgeInv

	// Stage 6.8: Persist findings snapshot (generation-scoped). The snapshot
	// query is explicitly scoped to THIS generation's composite edges (via the
	// generations set tagged in stage 6.4), so a foreign/stale composite edge
	// left in the graph by another scope's generation cannot be re-stamped with
	// this generation_id and re-surfaced as one of this scan's findings.
	snapshotState := sdkingest.StageSkipped
	if p.findingStore != nil && p.graphDB != nil {
		snapshot, qErr := analysis.QueryFindingsScoped(ctx, p.graphDB, "", generationID)
		if qErr != nil {
			slog.Warn("findings snapshot query failed", "error", qErr)
			snapshotState = sdkingest.StageFailed
		} else {
			for i := range snapshot {
				snapshot[i].GenerationID = generationID
				snapshot[i].Lifecycle = "active"
				p.enrichFindingOccurrence(ctx, &snapshot[i])
			}
			if iErr := p.findingStore.InsertFindings(ctx, data.Meta.ScanID, snapshot); iErr != nil {
				slog.Warn("findings snapshot insert failed", "error", iErr)
				snapshotState = sdkingest.StageFailed
			} else {
				snapshotState = sdkingest.StageSucceeded
				slog.Info("findings snapshot persisted", "scan_id", data.Meta.ScanID, "generation_id", generationID, "count", len(snapshot))
			}
		}
	}
	stages.set(sdkingest.StageSnapshot, snapshotState, nil)

	// Stage 7: Record completion status + committed counts (historical path).
	status := model.ScanStatusCompleted
	scanErr := ""
	if ppErr != nil {
		status = model.ScanStatusCompletedWithErrors
		scanErr = fmt.Sprintf("post-processing: %v", ppErr)
	}
	if p.scanStore != nil {
		if err := p.scanStore.UpdateScan(ctx, data.Meta.ScanID, status, nodesWritten, edgesWritten, scanErr); err != nil {
			slog.Warn("failed to update scan record", "error", err)
		}
	}

	// Stage 8: Promotion. A generation becomes the default read target only
	// when EVERY required stage completed successfully. "Required" means:
	//   - Write: strictly Succeeded. A failed OR partial write (which includes
	//     a tagging failure — tagging degrades the write stage to partial)
	//     means the generation's facts are not fully committed/attributed, so
	//     promoting it could surface a fact the generations set does not cover
	//     (untracked) or hide one it should. Only a clean, fully-tagged write
	//     is promotable.
	//   - Post-processing: Succeeded or Skipped (no graph/processors). A FAILED
	//     post-process means the composite (attack-path) edges are incomplete,
	//     so the promoted view would understate reachability — not promotable.
	//   - Snapshot: Succeeded or Skipped (no finding store). A FAILED snapshot
	//     means the persisted findings do not match the graph, so list/detail
	//     parity is broken — not promotable.
	// A generation that fails the gate is still recorded with honest per-stage
	// state (disclosed via API completeness) but never becomes current.
	promotable := stages.state(sdkingest.StageWrite) == sdkingest.StageSucceeded &&
		stageOK(stages.state(sdkingest.StagePostProcessing)) &&
		stageOK(snapshotState)

	// Coverage-aware promotion gate: an incomplete (partial/failed/unknown)
	// generation must NOT demote a prior COMPLETE generation of the same scope.
	// Doing so would hide the last complete posture behind an incomplete read
	// (the current view scopes to the promoted generation, so a partial
	// re-scan of a subset would drop the complete generation's retained facts).
	// The incomplete generation is still recorded with honest per-stage/coverage
	// state (disclosed), just not promoted. When there is no complete incumbent
	// (first scan, or the incumbent was itself incomplete) the new generation
	// is promoted as the best available, still disclosed as incomplete.
	if promotable && !coverageStatus.IsClean() && priorCurrent != nil &&
		priorCurrent.IsCurrent && priorCurrent.CoverageStatus.IsClean() &&
		priorCurrent.GenerationID != generationID {
		promotable = false
		slog.Warn("incomplete generation not promoted over complete incumbent",
			"scope", scope, "incumbent", priorCurrent.ID, "incumbent_generation", priorCurrent.GenerationID,
			"coverage_status", coverageStatus)
	}

	// Durability gate (F4): persist the prerequisite stage outcomes BEFORE the
	// current pointer flips. Promotion exposes this generation as the default
	// read target, and API completeness requires the prerequisite stages
	// (write succeeded, post-processing + snapshot ok) to be recorded as
	// successful. If we promoted first and crashed before recording, the
	// promoted generation would be exposed with unknown/absent stage states and
	// completeness could never confirm it. Recording the prerequisites first
	// makes promotion safe to interrupt: a promoted generation always carries
	// its successful prerequisite outcomes.
	if p.scanStore != nil && promotable {
		prereq := &model.Scan{
			ID:             data.Meta.ScanID,
			Collector:      data.Meta.Collector,
			Scope:          scope,
			GenerationID:   generationID,
			CoverageStatus: coverageStatus,
			Coverage:       data.Meta.Coverage,
			StageStates:    stages.snapshot(),
			NodeInventory:  nodeInv,
			EdgeInventory:  edgeInv,
			CapturedAt:     capturedAt,
		}
		if err := p.scanStore.RecordGenerationOutcome(ctx, prereq); err != nil {
			// Cannot durably record prerequisites → do NOT promote. The
			// generation stays non-current with honest state rather than
			// becoming an unverifiable current pointer.
			slog.Warn("failed to record prerequisite outcome before promotion; skipping promotion", "error", err)
			promotable = false
		}
	}

	if p.scanStore != nil && promotable {
		if err := p.scanStore.PromoteGeneration(ctx, data.Meta.ScanID, scope); err != nil {
			slog.Warn("generation promotion failed", "error", err)
			stages.set(sdkingest.StagePromotion, sdkingest.StageFailed, err)
		} else {
			stages.set(sdkingest.StagePromotion, sdkingest.StageSucceeded, nil)
		}
	} else {
		stages.set(sdkingest.StagePromotion, sdkingest.StageSkipped, nil)
	}

	// Persist the full generation outcome (coverage, per-stage states,
	// inventory deltas). Kept distinct from UpdateScan so the historical
	// status/counts path stays stable.
	if p.scanStore != nil {
		outcome := &model.Scan{
			ID:             data.Meta.ScanID,
			Collector:      data.Meta.Collector,
			Scope:          scope,
			GenerationID:   generationID,
			CoverageStatus: coverageStatus,
			Coverage:       data.Meta.Coverage,
			StageStates:    stages.snapshot(),
			NodeInventory:  nodeInv,
			EdgeInventory:  edgeInv,
			CapturedAt:     capturedAt,
		}
		if err := p.scanStore.RecordGenerationOutcome(ctx, outcome); err != nil {
			slog.Warn("failed to record generation outcome", "error", err)
		}
	}

	result.Stages = stages.results()
	result.Status = stages.rollup()
	result.Duration = time.Since(start)
	slog.Info("ingest complete", "scan_id", data.Meta.ScanID, "generation_id", generationID,
		"nodes", nodesWritten, "edges", edgesWritten, "status", result.Status, "duration", result.Duration)
	return result, nil
}

// enrichFindingOccurrence reconstructs the evidence DAG + attack cost for a
// snapshot finding so the persisted occurrence carries the same typed evidence,
// nullable weight total, and missing-weight count the detail endpoint would
// derive. Best-effort: a failed reconstruction leaves the occurrence with its
// endpoints only and an explicitly incomplete DAG rather than aborting ingest.
func (p *Pipeline) enrichFindingOccurrence(ctx context.Context, f *model.Finding) {
	if p.graphDB == nil {
		return
	}
	compositeProps, err := analysis.GetCompositeEdgeProps(ctx, p.graphDB, f)
	if err != nil {
		slog.Debug("composite edge props lookup failed", "finding", f.ID, "error", err)
	}
	if len(compositeProps) > 0 {
		f.CompositeProps = cloneMap(compositeProps)
	}
	path, err := analysis.ReconstructAttackPath(ctx, p.graphDB, f, compositeProps)
	if err != nil {
		slog.Debug("attack path reconstruction failed", "finding", f.ID, "error", err)
	}
	dag := analysis.BuildEvidenceDAG(f, path, compositeProps)
	if dag != nil {
		if m, err := structToMap(dag); err == nil {
			f.EvidenceDAG = m
		}
		f.WeightTotal = dag.WeightTotal
		f.WeightMissingCount = dag.WeightMissingCount
		// AttackCost mirrors the fully-known path weight; nil (unknown) when a
		// required weight was absent — never a benign zero.
		f.AttackCost = dag.WeightTotal
	}
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// structToMap round-trips a value through JSON into a generic map so it can be
// stored in a JSONB column typed as map[string]any on the model.
func structToMap(v any) (map[string]any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// selectCredentialChainGenerations returns the CURRENT generations the
// cross-service credential chain may join across, EXCLUDING the owner's own
// scope (the owner generation supersedes any promoted generation of the same
// scope) and restricting participation to eligible artifacts. A nil store
// yields an empty set (the chain then only sees this ingest's generation).
//
// A failed read is RETURNED as an error, not swallowed: without knowing the
// current generation set, the chain would join against an unknown/incomplete
// set and understate reachability, so the caller must fail post-processing and
// gate promotion rather than promote a generation whose chain could not be
// selected.
//
// Note this reads only promoted (is_current) generations, and CurrentGenerations
// already excludes generations in a delete lifecycle, so a deleting/failed
// generation can never be pulled into a chain join.
func (p *Pipeline) selectCredentialChainGenerations(ctx context.Context, ownerScope string) ([]string, error) {
	if p.scanStore == nil {
		return nil, nil
	}
	scans, err := p.scanStore.CurrentGenerations(ctx)
	if err != nil {
		return nil, fmt.Errorf("current-generations lookup: %w", err)
	}
	var gens []string
	for i := range scans {
		s := scans[i]
		if s.GenerationID == "" {
			continue
		}
		if s.Scope == ownerScope {
			continue
		}
		if !chainEligibleGeneration(s) {
			continue
		}
		gens = appendUnique(gens, s.GenerationID)
	}
	return gens, nil
}

// ownerEligibleForCredentialChain reports whether the artifact CURRENTLY being
// ingested may itself run credential-chain processing. It applies the SAME gate
// as chainEligibleGeneration, so only an explicit config-bearing generation or a
// complete/partial loot generation runs the chain; an mcp/a2a/network re-ingest,
// or a failed/unknown-coverage loot/config artifact, is excluded and never
// re-attributes chain edges to a generation that makes no positive claim.
func ownerEligibleForCredentialChain(scope, collector string, coverage sdkingest.CollectionStatus) bool {
	return chainEligibleGeneration(model.Scan{Scope: scope, Collector: collector, CoverageStatus: coverage})
}

// chainEligibleGeneration gates which generations may anchor a credential-chain
// join, applied identically to the owner generation and to the OTHER-scope
// current generations selected around it. A generation qualifies only when it
// is a loot generation OR a config-bearing generation (the config collector, or
// the merged local `scan:local` bundle that runs it) AND it carries EXPLICIT
// coverage (complete or partial). A failed/unknown-coverage artifact makes no
// positive claim to anchor a chain on, and everything else (mcp/a2a/network
// sweeps) cannot add or remove a chain edge — both are excluded.
func chainEligibleGeneration(s model.Scan) bool {
	isLoot := strings.HasPrefix(s.Scope, scopeLootPrefix)
	configBearing := s.Collector == "config" || s.Scope == scopeScanLocal
	if !isLoot && !configBearing {
		return false
	}
	return s.CoverageStatus == sdkingest.StatusComplete || s.CoverageStatus == sdkingest.StatusPartial
}

// count runs a single-integer count query, logging and returning 0 on error so
// a flaky read degrades a metric rather than aborting the ingest.
func (p *Pipeline) count(ctx context.Context, cypher string, params map[string]any) int {
	n, err := queryCount(ctx, p.graphDB, cypher, params)
	if err != nil {
		slog.Warn("count query failed", "error", err)
		return 0
	}
	return n
}

// failGeneration records a failed/partial generation: the scan is marked
// failed with the committed counts, and the honest per-stage states +
// inventory (before-totals only) are persisted. The generation is NOT
// promoted, so default reads never see it.
func (p *Pipeline) failGeneration(ctx context.Context, meta sdkingest.IngestMeta, generationID string,
	coverageStatus sdkingest.CollectionStatus, capturedAt *time.Time, nodesWritten, edgesWritten int,
	stages *stageTracker, cause error) {
	if p.scanStore == nil {
		return
	}
	if err := p.scanStore.UpdateScan(ctx, meta.ScanID, model.ScanStatusFailed, nodesWritten, edgesWritten, cause.Error()); err != nil {
		slog.Warn("failed to record scan failure", "error", err)
	}
	stages.set(sdkingest.StageSnapshot, sdkingest.StageSkipped, nil)
	stages.set(sdkingest.StagePromotion, sdkingest.StageSkipped, nil)
	outcome := &model.Scan{
		ID:             meta.ScanID,
		Collector:      meta.Collector,
		Scope:          collectorScope(meta),
		GenerationID:   generationID,
		CoverageStatus: coverageStatus,
		Coverage:       meta.Coverage,
		StageStates:    stages.snapshot(),
		CapturedAt:     capturedAt,
	}
	if err := p.scanStore.RecordGenerationOutcome(ctx, outcome); err != nil {
		slog.Warn("failed to record failed generation outcome", "error", err)
	}
}

func schemaVersionOf(meta sdkingest.IngestMeta) int {
	if meta.SchemaVersion > 0 {
		return meta.SchemaVersion
	}
	return sdkingest.CurrentSchemaVersion
}

func identityVersionOf(meta sdkingest.IngestMeta) int {
	if meta.IdentityVersion > 0 {
		return meta.IdentityVersion
	}
	return sdkingest.CurrentIdentityVersion
}

func parseCaptureTime(ts string) *time.Time {
	if ts == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		u := t.UTC()
		return &u
	}
	return nil
}

func clampNonNeg(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// stampProvenance records the source collector and capture time on every raw
// node/edge observation this artifact carries. These become the inputs the
// logical-current projection orders on (collector authority, then capture /
// completion time), so a shared objectid observed by two collectors resolves
// conflicting properties deterministically. Composite edges emitted later by
// the post-processors set their own source_collector and are not touched here.
func stampProvenance(data *sdkingest.IngestData) {
	collector := data.Meta.Collector
	captured := data.Meta.Timestamp
	for i := range data.Graph.Nodes {
		if data.Graph.Nodes[i].Properties == nil {
			data.Graph.Nodes[i].Properties = map[string]any{}
		}
		data.Graph.Nodes[i].Properties["source_collector"] = collector
		if captured != "" {
			data.Graph.Nodes[i].Properties["captured_at"] = captured
		}
	}
	for i := range data.Graph.Edges {
		if data.Graph.Edges[i].Properties == nil {
			data.Graph.Edges[i].Properties = map[string]any{}
		}
		data.Graph.Edges[i].Properties["source_collector"] = collector
		if captured != "" {
			data.Graph.Edges[i].Properties["captured_at"] = captured
		}
	}
}

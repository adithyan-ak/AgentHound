package appdb

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/jackc/pgx/v5"
)

func updateCoverageLimitationsTx(
	ctx context.Context,
	tx pgx.Tx,
	scan model.Scan,
	report *sdkingest.CollectionReport,
	authoritativeRoots []sdkingest.CoverageRoot,
) error {
	if report == nil {
		return nil
	}

	observedAt := time.Now().UTC()
	if scan.ArtifactObservedAt != nil {
		observedAt = scan.ArtifactObservedAt.UTC()
	}
	states := sdkingest.CoverageStates(report)
	parents := sdkingest.CoverageParents(report)
	keys := make([]string, 0, len(states))
	for key := range states {
		if key = strings.TrimSpace(key); key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		state := states[key]
		switch state {
		case sdkingest.OutcomeComplete, sdkingest.OutcomeNotApplicable:
			if _, err := tx.Exec(ctx,
				`DELETE FROM coverage_limitations WHERE coverage_key = $1`,
				key,
			); err != nil {
				return fmt.Errorf("clear coverage limitation %s: %w", key, err)
			}
		case sdkingest.OutcomeUnknown, sdkingest.OutcomePartial,
			sdkingest.OutcomeFailed, sdkingest.OutcomeTruncated:
			if _, err := tx.Exec(ctx, `INSERT INTO coverage_limitations
				    (coverage_key, parent_coverage_key, state, scan_id, observed_at)
				VALUES ($1, NULLIF($2, ''), $3, $4, $5)
				ON CONFLICT (coverage_key) DO UPDATE SET
				    parent_coverage_key = EXCLUDED.parent_coverage_key,
				    state = EXCLUDED.state,
				    scan_id = EXCLUDED.scan_id,
				    observed_at = EXCLUDED.observed_at`,
				key,
				parents[key],
				state,
				scan.ID,
				observedAt,
			); err != nil {
				return fmt.Errorf("record coverage limitation %s: %w", key, err)
			}
		}
	}

	for _, root := range authoritativeRoots {
		rootKey := strings.TrimSpace(root.CoverageKey)
		if rootKey == "" {
			continue
		}
		activeChildren := normalizeCoverageKeys(root.ChildCoverageKeys)
		if len(activeChildren) == 0 {
			if _, err := tx.Exec(ctx,
				`DELETE FROM coverage_limitations WHERE parent_coverage_key = $1`,
				rootKey,
			); err != nil {
				return fmt.Errorf("retire coverage limitations under %s: %w", rootKey, err)
			}
			continue
		}
		if _, err := tx.Exec(ctx, `DELETE FROM coverage_limitations
			WHERE parent_coverage_key = $1
			  AND NOT (coverage_key = ANY($2::text[]))`,
			rootKey,
			activeChildren,
		); err != nil {
			return fmt.Errorf("retire coverage limitations under %s: %w", rootKey, err)
		}
	}
	return nil
}

type coverageLimitationQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func listActiveCoverageLimitations(
	ctx context.Context,
	querier coverageLimitationQuerier,
) ([]model.PostureCoverageLimitation, error) {
	rows, err := querier.Query(ctx, `SELECT
	    coverage_key,
	    coalesce(parent_coverage_key, ''),
	    state,
	    scan_id,
	    observed_at
	FROM coverage_limitations
	ORDER BY coverage_key`)
	if err != nil {
		return nil, fmt.Errorf("read active coverage limitations: %w", err)
	}
	defer rows.Close()

	limitations := make([]model.PostureCoverageLimitation, 0)
	for rows.Next() {
		var limitation model.PostureCoverageLimitation
		if err := rows.Scan(
			&limitation.CoverageKey,
			&limitation.ParentCoverageKey,
			&limitation.State,
			&limitation.ScanID,
			&limitation.ObservedAt,
		); err != nil {
			return nil, fmt.Errorf("scan active coverage limitation: %w", err)
		}
		limitations = append(limitations, limitation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read active coverage limitations: %w", err)
	}
	return limitations, nil
}

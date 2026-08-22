-- Hash-only instruction findings cannot support the current evidence contract.
-- Remove them from finding state and immutable posture exports; a fresh scan
-- recreates only findings with bounded, inspectable content evidence.
DELETE FROM finding_triage
WHERE fingerprint IN (
    SELECT DISTINCT fingerprint
    FROM findings
    WHERE edge_kind = 'POISONED_INSTRUCTIONS'
);

DELETE FROM findings
WHERE edge_kind = 'POISONED_INSTRUCTIONS';

WITH publication_rewrite AS (
    SELECT
        pp.revision,
        COALESCE(
            jsonb_agg(item.value ORDER BY item.ordinality)
                FILTER (WHERE item.value IS NOT NULL
                    AND item.value ->> 'edge_kind' <> 'POISONED_INSTRUCTIONS'),
            '[]'::jsonb
        ) AS retained_findings,
        count(item.value) FILTER (
            WHERE item.value IS NOT NULL
              AND item.value ->> 'edge_kind' <> 'POISONED_INSTRUCTIONS'
        ) AS retained_count,
        COALESCE((pp.export #>> '{graph_after,edge_counts,POISONED_INSTRUCTIONS}')::bigint, 0) AS after_removed,
        COALESCE((pp.export #>> '{graph_before,edge_counts,POISONED_INSTRUCTIONS}')::bigint, 0) AS before_removed
    FROM posture_publications pp
    LEFT JOIN LATERAL jsonb_array_elements(
        COALESCE(pp.export -> 'findings', '[]'::jsonb)
    ) WITH ORDINALITY AS item(value, ordinality) ON TRUE
    GROUP BY pp.revision, pp.export
), rewritten AS (
    SELECT
        pp.revision,
        pr.after_removed,
        pr.before_removed,
        jsonb_set(
            jsonb_set(
                jsonb_set(
                    jsonb_set(
                        jsonb_set(
                            pp.export,
                            '{findings}',
                            pr.retained_findings,
                            true
                        ),
                        '{limits,findings,returned}',
                        to_jsonb(pr.retained_count),
                        true
                    ),
                    '{limits,findings,total}',
                    to_jsonb(pr.retained_count),
                    true
                ),
                '{graph_after,edge_counts}',
                COALESCE(pp.export #> '{graph_after,edge_counts}', '{}'::jsonb) - 'POISONED_INSTRUCTIONS',
                true
            ),
            '{graph_after,total_edges}',
            to_jsonb(GREATEST(
                COALESCE((pp.export #>> '{graph_after,total_edges}')::bigint, 0) - pr.after_removed,
                0
            )),
            true
        ) AS next_export,
        jsonb_set(
            COALESCE(pp.graph_stats, '{}'::jsonb),
            '{edge_counts}',
            COALESCE(pp.graph_stats -> 'edge_counts', '{}'::jsonb) - 'POISONED_INSTRUCTIONS',
            true
        ) AS next_graph_stats
    FROM posture_publications pp
    JOIN publication_rewrite pr ON pr.revision = pp.revision
), with_graph_before AS (
    SELECT
        revision,
        CASE
            WHEN next_export ? 'graph_before' THEN jsonb_set(
                jsonb_set(
                    next_export,
                    '{graph_before,edge_counts}',
                    COALESCE(next_export #> '{graph_before,edge_counts}', '{}'::jsonb) - 'POISONED_INSTRUCTIONS',
                    true
                ),
                '{graph_before,total_edges}',
                to_jsonb(GREATEST(
                    COALESCE((next_export #>> '{graph_before,total_edges}')::bigint, 0) - before_removed,
                    0
                )),
                true
            )
            ELSE next_export
        END AS next_export,
        jsonb_set(
            next_graph_stats,
            '{total_edges}',
            to_jsonb(GREATEST(
                COALESCE((next_graph_stats ->> 'total_edges')::bigint, 0) - after_removed,
                0
            )),
            true
        ) AS next_graph_stats
    FROM rewritten
)
UPDATE posture_publications pp
SET export = rewrite.next_export,
    graph_stats = rewrite.next_graph_stats
FROM with_graph_before rewrite
WHERE pp.revision = rewrite.revision;

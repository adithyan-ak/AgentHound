import type { APINode } from "@entities/graph/dto";
import type { BuildOptions, LogicalClusterNode, OrphanClusterData } from "./types";
import { kindTag, nodeLabel } from "./build-nodes";

/**
 * Emit one cluster placeholder per kind for the collected orphans. These render
 * as a distinct "stacked hex" with a count badge. Skipped entirely when
 * showOrphans is false, there are no orphans, or the lens dims others (those
 * lenses render orphans as dimmed context instead).
 *
 * The caller prepends these to the node list so ELK's `considerModelOrder`
 * hint places them above the connected nodes within each column.
 */
export function buildOrphanClusters(
  orphanByKind: Record<string, APINode[]>,
  opts: BuildOptions,
  orphanCount: number,
): LogicalClusterNode[] {
  const showOrphans = opts.showOrphans ?? false;
  if (!showOrphans || orphanCount === 0 || opts.lens.dimOthers) return [];

  const clusterNodes: LogicalClusterNode[] = [];
  for (const [kind, members] of Object.entries(orphanByKind)) {
    const orphanNodes = members.map((m) => ({
      id: m.id,
      name: nodeLabel(m),
      kind,
    }));
    clusterNodes.push({
      id: `orphan-cluster-${kind}`,
      data: {
        kind,
        kindTag: kindTag(kind),
        lensLabel: opts.lens.label,
        count: members.length,
        orphanNodes,
      } satisfies OrphanClusterData,
    });
  }
  return clusterNodes;
}

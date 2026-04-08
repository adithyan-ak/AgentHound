import type { MultiDirectedGraph } from "graphology";
import FA2Layout from "graphology-layout-forceatlas2/worker";

const FA2_SETTINGS = {
  gravity: 1,
  scalingRatio: 2,
  strongGravityMode: true,
  slowDown: 5,
  barnesHutOptimize: true,
  barnesHutTheta: 0.5,
};

const MAX_NODES_FOR_LAYOUT = 5000;

export function runLayout(
  graph: MultiDirectedGraph,
  duration = 2000,
): Promise<void> {
  if (graph.order > MAX_NODES_FOR_LAYOUT) {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    const layout = new FA2Layout(graph, { settings: FA2_SETTINGS });
    layout.start();

    setTimeout(() => {
      layout.stop();
      layout.kill();
      resolve();
    }, duration);
  });
}

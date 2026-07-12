---
paths:
  - "sdk/ingest/**"
  - "server/internal/graph/**"
  - "server/internal/ingest/**"
---
# Graph Schema Rules

- 23 collector-produced node kinds = 23 in AllNodeLabels
- 18 raw edge kinds + 12 composite = 30 in AllowedEdgeKinds
- AIService is an UmbrellaLabel — skip uniqueness constraint in schema-init
- Concrete node uniqueness is `observation_id` (generation + logical `objectid`); never restore per-label uniqueness on logical `objectid`
- All properties stored as snake_case. Normalizer converts camelCase from collector JSON.
- Edge structs carry: Source, Target, Kind, SourceKind, TargetKind, Properties
- EdgeKindEndpoints maps each edge to expected source/target node labels
- When adding a node kind: update AllowedNodeKinds, AllNodeLabels, model_test.go counts
- When adding an edge kind: update RawEdgeKinds, AllowedEdgeKinds, EdgeKindEndpoints, model_test.go counts

---
paths:
  - "sdk/ingest/**"
  - "server/internal/graph/**"
  - "server/internal/ingest/**"
---
# Graph Schema Rules

- 23 collector-produced node kinds in AllNodeLabels
- 18 raw edge kinds + 12 composite = 30 in AllowedEdgeKinds
- AIService is an UmbrellaLabel — skip uniqueness constraint in schema-init
- All collector and stored properties use canonical snake_case; non-canonical
  keys are rejected before normalization.
- Edge structs carry: Source, Target, Kind, SourceKind, TargetKind, Properties
- EdgeKindEndpoints maps each edge to expected source/target node labels
- When adding a node kind: update AllowedNodeKinds, AllNodeLabels, model_test.go counts
- When adding an edge kind: update RawEdgeKinds, AllowedEdgeKinds, EdgeKindEndpoints, model_test.go counts

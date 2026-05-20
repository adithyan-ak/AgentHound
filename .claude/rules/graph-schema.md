---
paths:
  - "sdk/ingest/**"
  - "server/internal/graph/**"
  - "server/internal/ingest/**"
---
# Graph Schema Rules

- 23 collector-produced node kinds + 2 synthetic (ResourceGroup, TrustZone) = 25 in AllNodeLabels
- 17 raw edge kinds + 8 composite = 25 in AllowedEdgeKinds
- AIService is an UmbrellaLabel — skip uniqueness constraint in schema-init
- All properties stored as snake_case. Normalizer converts camelCase from collector JSON.
- Edge structs carry: Source, Target, Kind, SourceKind, TargetKind, Properties
- EdgeKindEndpoints maps each edge to expected source/target node labels
- When adding a node kind: update AllowedNodeKinds, AllNodeLabels, model_test.go counts
- When adding an edge kind: update RawEdgeKinds, AllowedEdgeKinds, EdgeKindEndpoints, model_test.go counts

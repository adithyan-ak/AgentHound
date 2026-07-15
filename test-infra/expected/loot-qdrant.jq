(.graph.nodes | any(.kinds | index("QdrantInstance")))
and
(
  (.graph.nodes | any(.kinds | index("MCPResource")))
  or
  ((.graph.nodes[] | select(.kinds | index("QdrantInstance")) | .properties.collection_count // 0) | tonumber >= 2)
)
and
((.meta.collection.state == "complete") or (.meta.collection.state == "partial"))

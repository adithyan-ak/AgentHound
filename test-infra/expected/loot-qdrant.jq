.meta.collection.state == "complete"
and (.meta.extra.partial_errors | length) == 0
and (.graph.nodes | any(
  (.kinds | index("QdrantInstance")) and
  .properties.endpoint == "http://qdrant:6333" and
  .properties.collection_count == 2 and
  .properties.collections == ["chat-history","docs"] and
  .properties.total_points == 4 and
  .properties.points_scrolled_resources == 4
))
and ([.graph.nodes[] | select(.kinds | index("MCPResource")) | .properties.name] | sort)
  == ["chat-history/101","chat-history/102","docs/1","docs/2"]
and ([.graph.edges[] | select(.kind == "PROVIDES_RESOURCE")] | length) == 4

(.graph.nodes | any(.kinds | index("ExtractedTrainingSignal")))
and
(.graph.edges | any(.kind == "EXTRACTED_FROM"))
and
(.meta.collection.state == "complete")

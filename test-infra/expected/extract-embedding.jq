.meta.collection.state == "complete"
and .meta.extra.source_node_id == "sha256:4482e450f9f605ebe76de9243b6ce516c859b29e3a173b42af8425914009bef2"
and .meta.extra.engagement_id == "RTV-EXTRACT"
and (.graph.nodes | length) == 3
and (.graph.nodes | any(
  .id == "sha256:4482e450f9f605ebe76de9243b6ce516c859b29e3a173b42af8425914009bef2" and
  .kinds == ["AIModel"] and
  .properties == {} and
  .property_semantics == "reference_only"
))
and ([.graph.nodes[] | select(.kinds == ["ExtractedTrainingSignal"]) | {
  kind:.kinds,
  token_index:.properties.token_index,
  token_string:.properties.token_string,
  magnitude:.properties.magnitude,
  z_score:.properties.z_score,
  confidence:.properties.confidence,
  source_model_id:.properties.source_model_id,
  engagement_id:.properties.engagement_id,
  method:.properties.method
}] | sort_by(.token_index) | .[0] as $first | .[1] as $second |
  ($first.kind == ["ExtractedTrainingSignal"]) and
  ($first.token_index == 465) and ($first.token_string == "“") and
  (($first.magnitude - 3.147420937540306) | fabs < 1e-12) and
  (($first.z_score - 1.7697215378500182) | fabs < 1e-12) and
  ($first.confidence == 1) and
  ($second.kind == ["ExtractedTrainingSignal"]) and
  ($second.token_index == 477) and ($second.token_string == "0") and
  (($second.magnitude - 3.151688503213009) | fabs < 1e-12) and
  (($second.z_score - 1.7803608237941912) | fabs < 1e-12) and
  ($second.confidence == 1) and
  ([$first,$second] | all(
    .source_model_id == "sha256:4482e450f9f605ebe76de9243b6ce516c859b29e3a173b42af8425914009bef2" and
    .engagement_id == "RTV-EXTRACT" and .method == "embedding-outlier"
  )))
and (.graph.edges | length) == 2
and (([.graph.nodes[] | select(.kinds == ["ExtractedTrainingSignal"]) | .id] | sort) as $signal_ids |
  ([.graph.edges[] | select(
    .kind == "EXTRACTED_FROM" and
    .source == "sha256:4482e450f9f605ebe76de9243b6ce516c859b29e3a173b42af8425914009bef2" and
    .source_kind == "AIModel" and .target_kind == "ExtractedTrainingSignal" and
    .properties.method == "embedding-outlier" and
    .properties.evidence.engagement_id == "RTV-EXTRACT"
  ) | .target] | sort) == $signal_ids)

.meta.collection.state == "complete"
and .meta.extra.source_node_id == "hf://ggml-org/models@499bc8821c6b12b4e53c5bffcb21ec206f212d81/tinyllamas/stories260K.gguf"
and .meta.extra.engagement_id == "RTV-EXTRACT"
and (.graph.nodes | length) == 2
and ([.graph.nodes[] | {
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
    .source_model_id == "hf://ggml-org/models@499bc8821c6b12b4e53c5bffcb21ec206f212d81/tinyllamas/stories260K.gguf" and
    .engagement_id == "RTV-EXTRACT" and .method == "embedding-outlier"
  )))
and (.graph.edges | length) == 2
and ((.graph.nodes | map(.id) | sort) as $signal_ids |
  ([.graph.edges[] | select(
    .kind == "EXTRACTED_FROM" and
    .source == "hf://ggml-org/models@499bc8821c6b12b4e53c5bffcb21ec206f212d81/tinyllamas/stories260K.gguf" and
    .source_kind == "AIModel" and .target_kind == "ExtractedTrainingSignal" and
    .properties.method == "embedding-outlier" and
    .properties.evidence.engagement_id == "RTV-EXTRACT"
  ) | .target] | sort) == $signal_ids)

# `/v1/models` fixture provenance

This is an authored, deterministic fixture, not a claim that these exact bytes
were captured from a running vLLM deployment.

Its shape comes from two primary vLLM sources:

- The official vLLM serving documentation lists `GET /v1/models` as the route
  for listing available models:
  <https://docs.vllm.ai/en/stable/serving/online_serving/>
- vLLM v0.11.0 defines `ModelList` as `{"object":"list","data":[...]}` and
  `ModelCard` with the `id`, `object`, `created`, `owned_by`, `root`, `parent`,
  `max_model_len`, and `permission` fields used here:
  <https://github.com/vllm-project/vllm/blob/v0.11.0/vllm/entrypoints/openai/protocol.py>

The model identifier is a public Hugging Face-style identifier. The `created`
value is deliberately fixed, rather than pretending to preserve the
runtime-generated timestamp that a live vLLM process would return.

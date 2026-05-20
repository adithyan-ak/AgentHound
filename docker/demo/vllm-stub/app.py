"""vLLM fingerprint stub — answers /v1/models with a canonical OpenAI
list response. This is the minimum surface the v0.3 vLLM fingerprinter
inspects (sdk/rules/builtin/fingerprints/vllm.yaml)."""
from fastapi import FastAPI

app = FastAPI()


@app.get("/v1/models")
def models():
    return {
        "object": "list",
        "data": [
            {
                "id": "meta-llama/Llama-3.1-8B-Instruct",
                "object": "model",
                "created": 1735689600,
                "owned_by": "vllm",
            }
        ],
    }

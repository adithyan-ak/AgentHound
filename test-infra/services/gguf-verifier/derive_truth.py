"""Derive embedding-outlier truth with llama.cpp's official GGUF reader."""

import hashlib
import json
import math
import sys

import gguf


def main(path: str, threshold: float) -> None:
    reader = gguf.GGUFReader(path)
    tensor = next(t for t in reader.tensors if t.name == "token_embd.weight")
    rows = gguf.dequantize(tensor.data, tensor.tensor_type)
    token_field = reader.fields["tokenizer.ggml.tokens"]
    tokens = [
        bytes(token_field.parts[index]).decode("utf-8")
        for index in token_field.data
    ]

    norms = []
    for row in rows:
        total = 0.0
        for item in row:
            value = float(item)
            total += value * value
        norms.append(math.sqrt(total))

    mean = sum(norms) / len(norms)
    variance = sum(value * value for value in norms) / len(norms) - mean * mean
    stddev = math.sqrt(max(variance, 0.0))
    signals = []
    for index, magnitude in enumerate(norms):
        z_score = (magnitude - mean) / stddev
        if z_score >= threshold:
            signals.append(
                {
                    "token_index": index,
                    "token_string": tokens[index],
                    "magnitude": magnitude,
                    "z_score": z_score,
                    "confidence": min(z_score / threshold, 1.0),
                }
            )

    with open(path, "rb") as artifact:
        digest = hashlib.sha256(artifact.read()).hexdigest()
    print(
        json.dumps(
            {
                "reader": "llama.cpp gguf-py 0.17.1",
                "artifact_sha256": digest,
                "tensor": tensor.name,
                "tensor_shape": [int(item) for item in tensor.shape],
                "row_shape": [int(item) for item in rows.shape],
                "threshold": threshold,
                "mean_norm": mean,
                "stddev": stddev,
                "signals": signals,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main(sys.argv[1], float(sys.argv[2]))

"""Regenerate the independent GGUF parser regression.

Run in an isolated environment containing exactly gguf==0.17.1 and numpy.
The resulting checksum is recorded in UPSTREAM.md.
"""

from pathlib import Path

import numpy as np
from gguf import GGUFWriter


OUTPUT = Path(__file__).with_name("gguf-py-0.17.1.gguf")
TOKENS = ["<pad>", "<eos>", "alpha", "beta", "[upstream_signal]", "[upstream_tool]"]
EMBEDDINGS = np.array(
    [
        [0.1, 0.2, 0.3, 0.4],
        [0.2, 0.3, 0.4, 0.5],
        [0.3, 0.4, 0.5, 0.6],
        [0.4, 0.5, 0.6, 0.7],
        [3.0, 3.1, 3.2, 3.3],
        [4.0, 4.1, 4.2, 4.3],
    ],
    dtype=np.float32,
)

writer = GGUFWriter(OUTPUT, "llama")
writer.add_token_list(TOKENS)
writer.add_tensor("token_embd.weight", EMBEDDINGS)
writer.write_header_to_file()
writer.write_kv_data_to_file()
writer.write_tensors_to_file()
writer.close()

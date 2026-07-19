//go:build ignore

// gen_fixture.go generates testdata/extract/synthetic.gguf — a minimal
// valid GGUF file with a planted embedding matrix and tokenizer vocab
// for testing the embedding-inversion Extractor.
//
// Run: go run testdata/extract/gen_fixture.go
package main

import (
	"encoding/binary"
	"math"
	"os"
)

func main() {
	f, err := os.Create("testdata/extract/synthetic.gguf")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// GGUF header: magic + version + tensor_count + metadata_kv_count
	f.Write([]byte("GGUF"))
	binary.Write(f, binary.LittleEndian, uint32(3)) // version 3
	binary.Write(f, binary.LittleEndian, uint64(1)) // 1 tensor
	binary.Write(f, binary.LittleEndian, uint64(1)) // 1 metadata KV

	// Metadata KV: "tokenizer.ggml.tokens" = array of strings
	writeString(f, "tokenizer.ggml.tokens")
	binary.Write(f, binary.LittleEndian, uint32(9))  // type = array
	binary.Write(f, binary.LittleEndian, uint32(8))  // array element type = string
	binary.Write(f, binary.LittleEndian, uint64(10)) // array length = 10 tokens
	tokens := []string{
		"<pad>", "<eos>", "hello", "world", "the", "of", "to", "and",
		"[fine_tune_secret]", "[internal_tool_xyz]",
	}
	for _, tok := range tokens {
		writeString(f, tok)
	}

	// Tensor info: "token_embd.weight", 2 dims, [8, 10], F32, offset 0
	writeString(f, "token_embd.weight")
	binary.Write(f, binary.LittleEndian, uint32(2))  // n_dims = 2
	binary.Write(f, binary.LittleEndian, uint64(8))  // dim[0] = embed_dim = 8
	binary.Write(f, binary.LittleEndian, uint64(10)) // dim[1] = vocab_size = 10
	binary.Write(f, binary.LittleEndian, uint32(0))  // type = F32
	binary.Write(f, binary.LittleEndian, uint64(0))  // offset = 0

	// Align to 32 bytes for tensor data.
	pos, _ := f.Seek(0, 1)
	align := int64(32)
	padded := ((pos + align - 1) / align) * align
	pad := make([]byte, padded-pos)
	f.Write(pad)

	// Tensor data: 10 rows x 8 cols of float32.
	// Rows 0-7: normal embeddings (magnitude ~1.0)
	// Rows 8-9: outliers (magnitude ~4.0) — these are the "fine-tune signals"
	for row := 0; row < 10; row++ {
		for col := 0; col < 8; col++ {
			var val float32
			if row < 8 {
				// Normal: small values centered around 0.1-0.3
				val = 0.1 + float32(col)*0.025 + float32(row)*0.01
			} else {
				// Outlier: 4x magnitude
				val = 0.5 + float32(col)*0.1 + float32(row)*0.05
			}
			binary.Write(f, binary.LittleEndian, val)
		}
	}
}

func writeString(f *os.File, s string) {
	binary.Write(f, binary.LittleEndian, uint64(len(s)))
	f.Write([]byte(s))
}

// Verify: normal row L2 norm ~ sqrt(8 * 0.15^2) ~ 0.42
// Outlier row L2 norm ~ sqrt(8 * 0.85^2) ~ 2.4 → z-score well above 3.0
var _ = math.Sqrt // ensure import

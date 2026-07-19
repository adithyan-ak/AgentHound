//go:build ignore

// gen_q8_fixture.go generates testdata/extract/synthetic_q8.gguf — a GGUF
// file with Q8_0 quantized embedding tensor and multiple metadata KVs to
// exercise skipGGUFValue + readQ8_0Embeddings.
//
// Run: go run testdata/extract/gen_q8_fixture.go
package main

import (
	"encoding/binary"
	"math"
	"os"
)

func main() {
	f, err := os.Create("testdata/extract/synthetic_q8.gguf")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Header
	f.Write([]byte("GGUF"))
	binary.Write(f, binary.LittleEndian, uint32(3)) // version 3
	binary.Write(f, binary.LittleEndian, uint64(1)) // 1 tensor
	binary.Write(f, binary.LittleEndian, uint64(3)) // 3 metadata KVs

	// Metadata KV 1: "general.architecture" = string "llama"
	writeString(f, "general.architecture")
	binary.Write(f, binary.LittleEndian, uint32(8)) // type = string
	writeString(f, "llama")

	// Metadata KV 2: "general.context_length" = uint32(4096)
	writeString(f, "general.context_length")
	binary.Write(f, binary.LittleEndian, uint32(4)) // type = uint32
	binary.Write(f, binary.LittleEndian, uint32(4096))

	// Metadata KV 3: "tokenizer.ggml.tokens" = array of 10 strings
	writeString(f, "tokenizer.ggml.tokens")
	binary.Write(f, binary.LittleEndian, uint32(9))  // type = array
	binary.Write(f, binary.LittleEndian, uint32(8))  // element type = string
	binary.Write(f, binary.LittleEndian, uint64(10)) // length = 10
	tokens := []string{
		"<pad>", "<eos>", "hello", "world", "the", "of", "to", "and",
		"[secret_finetune_token]", "[internal_api_key]",
	}
	for _, tok := range tokens {
		writeString(f, tok)
	}

	// Tensor info: "token_embd.weight", 2 dims, [32, 10], Q8_0, offset 0
	// Using embedDim=32 so it aligns exactly with Q8_0 block size (1 block/row)
	writeString(f, "token_embd.weight")
	binary.Write(f, binary.LittleEndian, uint32(2))  // n_dims = 2
	binary.Write(f, binary.LittleEndian, uint64(32)) // dim[0] = embed_dim = 32
	binary.Write(f, binary.LittleEndian, uint64(10)) // dim[1] = vocab_size = 10
	binary.Write(f, binary.LittleEndian, uint32(8))  // type = Q8_0
	binary.Write(f, binary.LittleEndian, uint64(0))  // offset = 0

	// Align to 32 bytes
	pos, _ := f.Seek(0, 1)
	align := int64(32)
	padded := ((pos + align - 1) / align) * align
	pad := make([]byte, padded-pos)
	f.Write(pad)

	// Q8_0 tensor data: 10 rows, each row = 1 block of 34 bytes
	// Block format: 2 bytes (f16 scale) + 32 bytes (int8 values)
	// Rows 0-7: normal (scale ~0.01, values in [-10, 10])
	// Rows 8-9: outlier (scale ~0.1, values at max [-127, 127])
	for row := 0; row < 10; row++ {
		var scale float32
		var values [32]int8
		if row < 8 {
			// Normal embedding: small scale, moderate int8 values
			scale = 0.01
			for j := range values {
				values[j] = int8(5 + j%10) // magnitude per element: 0.05-0.14
			}
		} else {
			// Outlier: large scale, large int8 values
			scale = 0.1
			for j := range values {
				values[j] = int8(100 + j%28) // magnitude per element: 10.0-12.7
			}
		}
		binary.Write(f, binary.LittleEndian, float32ToFloat16(scale))
		binary.Write(f, binary.LittleEndian, values)
	}
}

func writeString(f *os.File, s string) {
	binary.Write(f, binary.LittleEndian, uint64(len(s)))
	f.Write([]byte(s))
}

func float32ToFloat16(f float32) uint16 {
	bits := math.Float32bits(f)
	sign := uint16((bits >> 16) & 0x8000)
	exp := int32((bits>>23)&0xff) - 127 + 15
	frac := bits & 0x7fffff

	switch {
	case exp <= 0:
		if exp < -10 {
			return sign
		}
		frac |= 0x800000
		shift := uint32(14 - exp)
		return sign | uint16(frac>>shift)
	case exp >= 0x1f:
		return sign | 0x7c00
	default:
		return sign | uint16(exp<<10) | uint16(frac>>13)
	}
}

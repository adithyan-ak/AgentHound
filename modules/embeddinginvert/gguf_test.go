package embeddinginvert

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fixturePath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "extract", "synthetic.gguf")
}

func TestParseGGUF_SyntheticFixture(t *testing.T) {
	gguf, err := ParseGGUF(fixturePath())
	if err != nil {
		t.Fatalf("ParseGGUF: %v", err)
	}
	if gguf.Version != 3 {
		t.Errorf("Version = %d, want 3", gguf.Version)
	}
	if gguf.VocabSize != 10 {
		t.Errorf("VocabSize = %d, want 10", gguf.VocabSize)
	}
	if gguf.EmbedDim != 8 {
		t.Errorf("EmbedDim = %d, want 8", gguf.EmbedDim)
	}
	if len(gguf.Tokens) != 10 {
		t.Errorf("Tokens len = %d, want 10", len(gguf.Tokens))
	}
	if gguf.Tokens[8] != "[fine_tune_secret]" {
		t.Errorf("Token[8] = %q, want [fine_tune_secret]", gguf.Tokens[8])
	}
	if gguf.Tokens[9] != "[internal_tool_xyz]" {
		t.Errorf("Token[9] = %q, want [internal_tool_xyz]", gguf.Tokens[9])
	}
	if len(gguf.Embeddings) != 10 {
		t.Fatalf("Embeddings rows = %d, want 10", len(gguf.Embeddings))
	}
	if len(gguf.Embeddings[0]) != 8 {
		t.Errorf("Embeddings cols = %d, want 8", len(gguf.Embeddings[0]))
	}
}

func TestParseGGUF_InvalidMagic(t *testing.T) {
	_, err := ParseGGUF("/dev/null")
	if err == nil {
		t.Error("expected error on /dev/null")
	}
}

func TestFloat16ToFloat32KnownValues(t *testing.T) {
	tests := []struct {
		name string
		in   uint16
		want float32
	}{
		{name: "one", in: 0x3c00, want: 1.0},
		{name: "half", in: 0x3800, want: 0.5},
		{name: "negative_two", in: 0xc000, want: -2.0},
		{name: "zero", in: 0x0000, want: 0.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := float16ToFloat32(tt.in)
			if got != tt.want {
				t.Fatalf("float16ToFloat32(%#04x) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestReadQ8_0EmbeddingsExactScale(t *testing.T) {
	var block bytes.Buffer
	if err := binary.Write(&block, binary.LittleEndian, uint16(0x3c00)); err != nil {
		t.Fatal(err)
	}
	values := [32]int8{}
	values[0] = 1
	values[1] = -2
	if err := binary.Write(&block, binary.LittleEndian, values); err != nil {
		t.Fatal(err)
	}
	rows, err := readQ8_0Embeddings(bytes.NewReader(block.Bytes()), 1, 32)
	if err != nil {
		t.Fatalf("readQ8_0Embeddings: %v", err)
	}
	if got := rows[0][0]; got != 1.0 {
		t.Fatalf("first value = %v, want 1.0", got)
	}
	if got := rows[0][1]; math.Abs(float64(got-(-2.0))) > 1e-6 {
		t.Fatalf("second value = %v, want -2.0", got)
	}
}

func TestParseGGUF_NotFound(t *testing.T) {
	_, err := ParseGGUF("/nonexistent/path.gguf")
	if err == nil {
		t.Error("expected error on missing file")
	}
}

// ggufHeader writes a minimal GGUF v3 header (magic, version, tensor
// count, metadata-kv count) so tests can craft malformed-but-parseable
// files without a real model artifact.
func ggufHeader(t *testing.T, tensorCount, metadataKVCount uint64) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	for _, v := range []any{uint32(ggufMagic), uint32(3), tensorCount, metadataKVCount} {
		if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	return &b
}

func writeTempGGUF(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "malformed.gguf")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestParseGGUF_MalformedCountsRejected proves a file-controlled count
// far larger than the file cannot drive a giant allocation or unbounded
// loop — the parser must return an error rather than panic or hang.
func TestParseGGUF_MalformedCountsRejected(t *testing.T) {
	cases := []struct {
		name            string
		tensorCount     uint64
		metadataKVCount uint64
	}{
		{"huge metadata kv count", 0, math.MaxUint64},
		{"huge tensor count", math.MaxUint64, 0},
		{"moderately oversized count", 1 << 40, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := ggufHeader(t, tc.tensorCount, tc.metadataKVCount)
			_, err := ParseGGUF(writeTempGGUF(t, buf.Bytes()))
			if err == nil {
				t.Fatal("expected error on malformed count, got nil")
			}
		})
	}
}

// TestParseGGUF_HugeTokenArrayRejected crafts a tokenizer array whose
// declared length dwarfs the file, ensuring the make([]string, 0, n)
// capacity hint cannot be abused.
func TestParseGGUF_HugeTokenArrayRejected(t *testing.T) {
	buf := ggufHeader(t, 0, 1) // one metadata KV
	writeStr := func(s string) {
		if err := binary.Write(buf, binary.LittleEndian, uint64(len(s))); err != nil {
			t.Fatal(err)
		}
		buf.WriteString(s)
	}
	writeStr("tokenizer.ggml.tokens")
	if err := binary.Write(buf, binary.LittleEndian, uint32(9)); err != nil { // type 9 = array
		t.Fatal(err)
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(8)); err != nil { // array elem type = string
		t.Fatal(err)
	}
	if err := binary.Write(buf, binary.LittleEndian, uint64(math.MaxUint64)); err != nil { // array length
		t.Fatal(err)
	}
	_, err := ParseGGUF(writeTempGGUF(t, buf.Bytes()))
	if err == nil {
		t.Fatal("expected error on oversized token array, got nil")
	}
}

// TestParseGGUF_TooManyTensorDimsRejected ensures a tensor declaring more
// than GGML_MAX_DIMS dimensions is rejected before sizing the dims slice.
func TestParseGGUF_TooManyTensorDimsRejected(t *testing.T) {
	buf := ggufHeader(t, 1, 0) // one tensor, no metadata
	// tensor name
	if err := binary.Write(buf, binary.LittleEndian, uint64(len("t"))); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("t")
	if err := binary.Write(buf, binary.LittleEndian, uint32(99)); err != nil { // nDims = 99 > max
		t.Fatal(err)
	}
	_, err := ParseGGUF(writeTempGGUF(t, buf.Bytes()))
	if err == nil {
		t.Fatal("expected error on excessive tensor dims, got nil")
	}
}

func q8FixturePath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "extract", "synthetic_q8.gguf")
}

func TestParseGGUF_Q8_0Fixture(t *testing.T) {
	gguf, err := ParseGGUF(q8FixturePath())
	if err != nil {
		t.Fatalf("ParseGGUF Q8_0: %v", err)
	}
	if gguf.Version != 3 {
		t.Errorf("Version = %d, want 3", gguf.Version)
	}
	if gguf.TensorType != ggmlTypeQ8_0 {
		t.Errorf("TensorType = %d, want Q8_0 (%d)", gguf.TensorType, ggmlTypeQ8_0)
	}
	if gguf.VocabSize != 10 {
		t.Errorf("VocabSize = %d, want 10", gguf.VocabSize)
	}
	if gguf.EmbedDim != 32 {
		t.Errorf("EmbedDim = %d, want 32", gguf.EmbedDim)
	}
	if len(gguf.Tokens) != 10 {
		t.Fatalf("Tokens len = %d, want 10", len(gguf.Tokens))
	}
	if gguf.Tokens[8] != "[secret_finetune_token]" {
		t.Errorf("Token[8] = %q, want [secret_finetune_token]", gguf.Tokens[8])
	}
	if len(gguf.Embeddings) != 10 {
		t.Fatalf("Embeddings rows = %d, want 10", len(gguf.Embeddings))
	}
	if len(gguf.Embeddings[0]) != 32 {
		t.Errorf("Embeddings cols = %d, want 32", len(gguf.Embeddings[0]))
	}
	// Verify dequantization produced non-zero values in expected range.
	// Normal rows: scale=0.01, values 5-14 → dequant magnitudes ~0.05-0.14
	// Outlier rows: scale=0.1, values 100-127 → dequant magnitudes ~10.0-12.7
	normalMag := l2Norm(gguf.Embeddings[0])
	outlierMag := l2Norm(gguf.Embeddings[8])
	if normalMag == 0 {
		t.Error("normal row has zero magnitude after dequant")
	}
	if outlierMag <= normalMag*2 {
		t.Errorf("outlier magnitude (%.3f) should be much larger than normal (%.3f)", outlierMag, normalMag)
	}
}

func TestParseGGUF_MultipleMetadataKeys(t *testing.T) {
	// The Q8_0 fixture has 3 metadata KVs: general.architecture (string),
	// general.context_length (uint32), tokenizer.ggml.tokens (array).
	// This exercises skipGGUFValue for string + uint32 types before
	// hitting the tokenizer array. If skipGGUFValue is broken, parsing
	// would either panic or produce wrong token data.
	gguf, err := ParseGGUF(q8FixturePath())
	if err != nil {
		t.Fatalf("ParseGGUF with multi-KV: %v", err)
	}
	if len(gguf.Tokens) != 10 {
		t.Errorf("after skipping 2 non-tokenizer KVs, Tokens len = %d, want 10", len(gguf.Tokens))
	}
	if gguf.Tokens[0] != "<pad>" {
		t.Errorf("first token after skip = %q, want <pad>", gguf.Tokens[0])
	}
}

func l2Norm(row []float32) float64 {
	var sum float64
	for _, v := range row {
		sum += float64(v) * float64(v)
	}
	return sum
}

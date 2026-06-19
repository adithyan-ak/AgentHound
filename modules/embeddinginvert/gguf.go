// Package embeddinginvert implements the v0.5 embedding-inversion Extractor.
//
// GGUF is the binary format used by llama.cpp (and Ollama) for storing
// quantized LLM weights. This file implements a minimal parser that
// extracts ONLY what the embedding-inversion algorithm needs:
//   - Tokenizer vocabulary (metadata key "tokenizer.ggml.tokens")
//   - Embedding tensor data (tensor named "token_embd.weight")
//
// Reference: https://github.com/ggerganov/ggml/blob/master/docs/gguf.md
package embeddinginvert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

const (
	ggufMagic   = 0x46475547 // "GGUF" little-endian
	ggufVersion = 3          // GGUF v3 (current as of llama.cpp b3000+)

	// GGML tensor types we support for the embedding layer.
	ggmlTypeF32  = 0
	ggmlTypeQ8_0 = 8

	// maxTensorDims bounds the per-tensor dimension count read from the
	// file before it sizes an allocation. GGML's on-disk format uses at
	// most 4 dimensions (GGML_MAX_DIMS); anything larger is malformed.
	maxTensorDims = 4
)

// GGUFFile holds the parsed metadata and embedding tensor from a GGUF file.
type GGUFFile struct {
	Version    uint32
	Tokens     []string    // tokenizer vocabulary (from metadata)
	EmbedDim   int         // embedding dimension (columns)
	VocabSize  int         // vocabulary size (rows)
	Embeddings [][]float32 // shape: [VocabSize][EmbedDim]
	TensorType uint32      // ggml type of the embedding tensor
}

// ParseGGUF reads a GGUF file and extracts the tokenizer vocabulary +
// embedding matrix. Returns an error if the file is not valid GGUF, if
// the embedding tensor is not found, or if the tensor type is unsupported.
func ParseGGUF(path string) (*GGUFFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open gguf: %w", err)
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat gguf: %w", err)
	}
	fileSize := st.Size()

	var magic uint32
	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != ggufMagic {
		return nil, fmt.Errorf("not a GGUF file (magic %08x, want %08x)", magic, ggufMagic)
	}

	var version uint32
	if err := binary.Read(f, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if version < 2 || version > 3 {
		return nil, fmt.Errorf("unsupported GGUF version %d (support 2-3)", version)
	}

	var tensorCount, metadataKVCount uint64
	if err := binary.Read(f, binary.LittleEndian, &tensorCount); err != nil {
		return nil, fmt.Errorf("read tensor count: %w", err)
	}
	if err := binary.Read(f, binary.LittleEndian, &metadataKVCount); err != nil {
		return nil, fmt.Errorf("read metadata kv count: %w", err)
	}
	// Every metadata KV and tensor info occupies at least one byte on
	// disk, so a count exceeding the file size is malformed. Reject it
	// before it drives an allocation or loop — a crafted count would
	// otherwise trigger a multi-GB make() panic or unbounded spin.
	if err := boundCount(tensorCount, fileSize, "tensor count"); err != nil {
		return nil, err
	}
	if err := boundCount(metadataKVCount, fileSize, "metadata kv count"); err != nil {
		return nil, err
	}

	result := &GGUFFile{Version: version}

	// Parse metadata KVs to find tokenizer vocabulary.
	for i := uint64(0); i < metadataKVCount; i++ {
		key, err := readGGUFString(f)
		if err != nil {
			return nil, fmt.Errorf("metadata kv %d key: %w", i, err)
		}
		var valueType uint32
		if err := binary.Read(f, binary.LittleEndian, &valueType); err != nil {
			return nil, fmt.Errorf("metadata kv %d type: %w", i, err)
		}
		if key == "tokenizer.ggml.tokens" && valueType == 9 {
			// Type 9 = array. Read array header.
			var arrType uint32
			var arrLen uint64
			if err := binary.Read(f, binary.LittleEndian, &arrType); err != nil {
				return nil, err
			}
			if err := binary.Read(f, binary.LittleEndian, &arrLen); err != nil {
				return nil, err
			}
			if err := boundCount(arrLen, fileSize, "token array length"); err != nil {
				return nil, err
			}
			result.Tokens = make([]string, 0, arrLen)
			for j := uint64(0); j < arrLen; j++ {
				s, err := readGGUFString(f)
				if err != nil {
					return nil, fmt.Errorf("token %d: %w", j, err)
				}
				result.Tokens = append(result.Tokens, s)
			}
		} else {
			if err := skipGGUFValue(f, valueType); err != nil {
				return nil, fmt.Errorf("skip metadata kv %d (%q): %w", i, key, err)
			}
		}
	}

	// Parse tensor infos to find the embedding tensor.
	type tensorInfo struct {
		name       string
		nDims      uint32
		dims       []uint64
		tensorType uint32
		offset     uint64
	}
	var embedInfo *tensorInfo
	for i := uint64(0); i < tensorCount; i++ {
		name, err := readGGUFString(f)
		if err != nil {
			return nil, fmt.Errorf("tensor %d name: %w", i, err)
		}
		var nDims uint32
		if err := binary.Read(f, binary.LittleEndian, &nDims); err != nil {
			return nil, fmt.Errorf("tensor %d ndims: %w", i, err)
		}
		if nDims > maxTensorDims {
			return nil, fmt.Errorf("tensor %d has %d dims, exceeds GGML max %d", i, nDims, maxTensorDims)
		}
		dims := make([]uint64, nDims)
		for d := uint32(0); d < nDims; d++ {
			if err := binary.Read(f, binary.LittleEndian, &dims[d]); err != nil {
				return nil, fmt.Errorf("tensor %d dim %d: %w", i, d, err)
			}
		}
		var tType uint32
		if err := binary.Read(f, binary.LittleEndian, &tType); err != nil {
			return nil, fmt.Errorf("tensor %d type: %w", i, err)
		}
		var offset uint64
		if err := binary.Read(f, binary.LittleEndian, &offset); err != nil {
			return nil, fmt.Errorf("tensor %d offset: %w", i, err)
		}
		if isEmbeddingTensor(name) {
			info := tensorInfo{name: name, nDims: nDims, dims: dims, tensorType: tType, offset: offset}
			embedInfo = &info
		}
	}
	if embedInfo == nil {
		return nil, errors.New("embedding tensor not found (looked for token_embd.weight, model.embed_tokens.weight)")
	}

	// The tensor data section starts at the next alignment boundary
	// after the current position. GGUF aligns tensor data to 32 bytes.
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	alignment := int64(32)
	dataStart := ((pos + alignment - 1) / alignment) * alignment

	if embedInfo.nDims != 2 {
		return nil, fmt.Errorf("embedding tensor has %d dims, want 2", embedInfo.nDims)
	}
	// The embedding matrix has at least one byte per element on disk, so
	// neither dimension (nor their product) can exceed the file size for
	// a well-formed file. Bounding here keeps the row/column allocations
	// in readF32Embeddings/readQ8_0Embeddings from a crafted-count panic.
	if err := boundCount(embedInfo.dims[0], fileSize, "embedding dim"); err != nil {
		return nil, err
	}
	if err := boundCount(embedInfo.dims[1], fileSize, "vocab size"); err != nil {
		return nil, err
	}
	result.EmbedDim = int(embedInfo.dims[0])
	result.VocabSize = int(embedInfo.dims[1])
	result.TensorType = embedInfo.tensorType

	tensorOffset := dataStart + int64(embedInfo.offset)
	if _, err := f.Seek(tensorOffset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek to embedding tensor: %w", err)
	}

	switch embedInfo.tensorType {
	case ggmlTypeF32:
		result.Embeddings, err = readF32Embeddings(f, result.VocabSize, result.EmbedDim)
	case ggmlTypeQ8_0:
		result.Embeddings, err = readQ8_0Embeddings(f, result.VocabSize, result.EmbedDim)
	default:
		return nil, fmt.Errorf("unsupported embedding tensor type %d (support F32=%d, Q8_0=%d)", embedInfo.tensorType, ggmlTypeF32, ggmlTypeQ8_0)
	}
	if err != nil {
		return nil, fmt.Errorf("read embedding data: %w", err)
	}

	return result, nil
}

// boundCount rejects a file-declared count that cannot fit in the file.
// Every counted element (metadata KV, tensor, array item, matrix cell)
// occupies at least one byte on disk, so a count larger than the file
// size is malformed. This caps allocations and loop bounds derived from
// untrusted header values without ever rejecting a well-formed file.
func boundCount(n uint64, fileSize int64, what string) error {
	if fileSize < 0 {
		return fmt.Errorf("invalid file size %d", fileSize)
	}
	if n > uint64(fileSize) {
		return fmt.Errorf("%s %d exceeds file size %d (malformed gguf)", what, n, fileSize)
	}
	return nil
}

func isEmbeddingTensor(name string) bool {
	switch name {
	case "token_embd.weight", "model.embed_tokens.weight":
		return true
	}
	return false
}

func readGGUFString(r io.Reader) (string, error) {
	var length uint64
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return "", err
	}
	if length > 1<<20 {
		return "", fmt.Errorf("string too long: %d bytes", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func skipGGUFValue(r io.ReadSeeker, valueType uint32) error {
	switch valueType {
	case 0: // uint8
		_, err := r.Seek(1, io.SeekCurrent)
		return err
	case 1: // int8
		_, err := r.Seek(1, io.SeekCurrent)
		return err
	case 2: // uint16
		_, err := r.Seek(2, io.SeekCurrent)
		return err
	case 3: // int16
		_, err := r.Seek(2, io.SeekCurrent)
		return err
	case 4: // uint32
		_, err := r.Seek(4, io.SeekCurrent)
		return err
	case 5: // int32
		_, err := r.Seek(4, io.SeekCurrent)
		return err
	case 6: // float32
		_, err := r.Seek(4, io.SeekCurrent)
		return err
	case 7: // bool
		_, err := r.Seek(1, io.SeekCurrent)
		return err
	case 8: // string
		s, err := readGGUFString(r)
		_ = s
		return err
	case 9: // array
		var arrType uint32
		var arrLen uint64
		if err := binary.Read(r, binary.LittleEndian, &arrType); err != nil {
			return err
		}
		if err := binary.Read(r, binary.LittleEndian, &arrLen); err != nil {
			return err
		}
		for i := uint64(0); i < arrLen; i++ {
			if err := skipGGUFValue(r, arrType); err != nil {
				return err
			}
		}
		return nil
	case 10: // uint64
		_, err := r.Seek(8, io.SeekCurrent)
		return err
	case 11: // int64
		_, err := r.Seek(8, io.SeekCurrent)
		return err
	case 12: // float64
		_, err := r.Seek(8, io.SeekCurrent)
		return err
	default:
		return fmt.Errorf("unknown gguf value type %d", valueType)
	}
}

func readF32Embeddings(r io.Reader, vocabSize, embedDim int) ([][]float32, error) {
	out := make([][]float32, vocabSize)
	for i := 0; i < vocabSize; i++ {
		row := make([]float32, embedDim)
		if err := binary.Read(r, binary.LittleEndian, row); err != nil {
			return nil, fmt.Errorf("row %d: %w", i, err)
		}
		out[i] = row
	}
	return out, nil
}

// readQ8_0Embeddings dequantizes Q8_0 blocks into float32. Q8_0 stores
// 32 int8 values + 1 float16 scale per block. Each row of the embedding
// matrix is stored as ceil(embedDim/32) blocks.
func readQ8_0Embeddings(r io.Reader, vocabSize, embedDim int) ([][]float32, error) {
	blockSize := 32
	blocksPerRow := (embedDim + blockSize - 1) / blockSize
	// Q8_0 block: 2 bytes (f16 scale) + 32 bytes (int8 data) = 34 bytes
	blockBytes := 2 + blockSize

	out := make([][]float32, vocabSize)
	buf := make([]byte, blocksPerRow*blockBytes)

	for i := 0; i < vocabSize; i++ {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("row %d: %w", i, err)
		}
		row := make([]float32, embedDim)
		for b := 0; b < blocksPerRow; b++ {
			blockStart := b * blockBytes
			scaleBits := binary.LittleEndian.Uint16(buf[blockStart : blockStart+2])
			scale := float16ToFloat32(scaleBits)
			for j := 0; j < blockSize; j++ {
				idx := b*blockSize + j
				if idx >= embedDim {
					break
				}
				val := int8(buf[blockStart+2+j])
				row[idx] = float32(val) * scale
			}
		}
		out[i] = row
	}
	return out, nil
}

func float16ToFloat32(h uint16) float32 {
	sign := uint32(h&0x8000) << 16
	exp := uint32((h >> 10) & 0x1f)
	frac := uint32(h & 0x03ff)

	switch exp {
	case 0:
		if frac == 0 {
			return math.Float32frombits(sign)
		}
		// Normalize subnormal half precision values.
		exp32 := int32(127 - 15 + 1)
		for frac&0x0400 == 0 {
			frac <<= 1
			exp32--
		}
		frac &= 0x03ff
		return math.Float32frombits(sign | (uint32(exp32) << 23) | (frac << 13))
	case 0x1f:
		return math.Float32frombits(sign | 0x7f800000 | (frac << 13))
	}

	exp32 := exp + (127 - 15)
	return math.Float32frombits(sign | (exp32 << 23) | (frac << 13))
}

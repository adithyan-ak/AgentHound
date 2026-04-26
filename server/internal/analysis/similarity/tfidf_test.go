package similarity

import (
	"math"
	"testing"
)

func TestTokenize_RemovesStopwords(t *testing.T) {
	tokens := Tokenize("the quick brown fox is in a box")
	for _, tok := range tokens {
		if _, stop := stopwords[tok]; stop {
			t.Errorf("stopword %q not removed", tok)
		}
	}
	expected := []string{"quick", "brown", "fox", "box"}
	if len(tokens) != len(expected) {
		t.Fatalf("got %d tokens %v, want %d %v", len(tokens), tokens, len(expected), expected)
	}
	for i, tok := range tokens {
		if tok != expected[i] {
			t.Errorf("token[%d] = %q, want %q", i, tok, expected[i])
		}
	}
}

func TestTokenize_LowercasesAndSplits(t *testing.T) {
	tokens := Tokenize("Hello-World! Test123")
	expected := []string{"hello", "world", "test123"}
	if len(tokens) != len(expected) {
		t.Fatalf("got %v, want %v", tokens, expected)
	}
	for i, tok := range tokens {
		if tok != expected[i] {
			t.Errorf("token[%d] = %q, want %q", i, tok, expected[i])
		}
	}
}

func TestTokenize_FiltersShortTokens(t *testing.T) {
	tokens := Tokenize("I go up")
	// "I" filtered (single char), "go" kept (2 chars), "up" kept
	expected := []string{"go", "up"}
	if len(tokens) != len(expected) {
		t.Fatalf("got %v, want %v", tokens, expected)
	}
}

func TestTokenize_EmptyInput(t *testing.T) {
	tokens := Tokenize("")
	if len(tokens) != 0 {
		t.Errorf("got %v for empty input, want empty", tokens)
	}
}

func TestCosineSimilarity_IdenticalDocuments(t *testing.T) {
	docs := []string{
		"manage kubernetes cluster deployments",
		"send email notifications to users",
		"manage kubernetes cluster deployments",
	}
	corpus := NewCorpus(docs)

	vecA := corpus.TFIDFVector(docs[0])
	vecB := corpus.TFIDFVector(docs[2])

	sim := CosineSimilarity(vecA, vecB)
	if math.Abs(sim-1.0) > 1e-9 {
		t.Errorf("identical documents: similarity = %f, want 1.0", sim)
	}
}

func TestCosineSimilarity_CompletelyDifferent(t *testing.T) {
	docs := []string{
		"manage kubernetes cluster deployments",
		"send email notifications to users",
	}
	corpus := NewCorpus(docs)

	vecA := corpus.TFIDFVector(docs[0])
	vecB := corpus.TFIDFVector(docs[1])

	sim := CosineSimilarity(vecA, vecB)
	if sim > 0.1 {
		t.Errorf("completely different documents: similarity = %f, want near 0.0", sim)
	}
}

func TestCosineSimilarity_EmptyDocuments(t *testing.T) {
	corpus := NewCorpus([]string{"some document"})

	vecA := corpus.TFIDFVector("")
	vecB := corpus.TFIDFVector("some document")

	if sim := CosineSimilarity(vecA, vecB); sim != 0.0 {
		t.Errorf("empty vs non-empty: similarity = %f, want 0.0", sim)
	}
	if sim := CosineSimilarity(vecA, nil); sim != 0.0 {
		t.Errorf("empty vs nil: similarity = %f, want 0.0", sim)
	}
	if sim := CosineSimilarity(nil, nil); sim != 0.0 {
		t.Errorf("nil vs nil: similarity = %f, want 0.0", sim)
	}
}

func TestCosineSimilarity_KnownCase(t *testing.T) {
	docs := []string{
		"search files read directory listing",
		"search documents query database index",
		"deploy container orchestrate cluster",
	}
	corpus := NewCorpus(docs)

	vecA := corpus.TFIDFVector(docs[0])
	vecB := corpus.TFIDFVector(docs[1])
	vecC := corpus.TFIDFVector(docs[2])

	simAB := CosineSimilarity(vecA, vecB)
	simAC := CosineSimilarity(vecA, vecC)

	// docs[0] and docs[1] share "search" → should be more similar than docs[0] and docs[2]
	if simAB <= simAC {
		t.Errorf("expected docs sharing 'search' to be more similar: AB=%f, AC=%f", simAB, simAC)
	}
	if simAB <= 0 {
		t.Errorf("overlapping docs should have positive similarity: %f", simAB)
	}
}

func TestCorpus_TFIDFVector_AllStopwords(t *testing.T) {
	corpus := NewCorpus([]string{"the and or but"})
	vec := corpus.TFIDFVector("the and or but")
	if vec != nil {
		t.Errorf("all-stopword document should produce nil vector, got %v", vec)
	}
}

func TestCorpus_SingleDocument(t *testing.T) {
	docs := []string{"agent performs file operations"}
	corpus := NewCorpus(docs)
	vec := corpus.TFIDFVector(docs[0])

	// With a single document, every term has df=1, N=1, so IDF = log(1/1) = 0.
	// All weights should be 0, producing a nil/empty vector.
	for term, weight := range vec {
		if weight != 0 {
			t.Errorf("single-doc corpus: term %q has weight %f, want 0", term, weight)
		}
	}
}

func TestNewCorpus_CountsDocumentFrequency(t *testing.T) {
	docs := []string{
		"file read write file", // "file" appears in this doc
		"file search query",    // "file" appears in this doc too
		"deploy container",     // "file" absent
	}
	corpus := NewCorpus(docs)

	if df := corpus.df["file"]; df != 2 {
		t.Errorf("df[file] = %d, want 2", df)
	}
	if df := corpus.df["deploy"]; df != 1 {
		t.Errorf("df[deploy] = %d, want 1", df)
	}
	if corpus.docCount != 3 {
		t.Errorf("docCount = %d, want 3", corpus.docCount)
	}
}
